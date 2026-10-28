// SPDX-License-Identifier: Apache-2.0
//
// The RDB constants and the LZF decompressor below were learned from Redis's
// and liblzf's own implementations, which are the descriptions of those
// formats that exist; the code here is rgx's own. The provenance is recorded
// in `NOTICE`.

//! Binary database files: MongoDB BSON and Redis RDB.
//!
//! Both are containers whose value is *structure* — a collection's field
//! names, a keyspace's keys — and neither has any text to search as it
//! stands, which is exactly the case `Reach::Reveal` exists for.
//!
//! **BSON** is a sequence of self-describing documents; every field name is
//! a NUL-terminated key in the file, so the keys are what grep wants and
//! the values ride along with them.
//!
//! **Redis RDB** is a compact snapshot: a header, some aux fields, then
//! per-key records whose type byte names which of a dozen shapes follows.
//! Every constant and every layout below follows Redis
//! `src/rdb.h` and `src/rdb.c` rather than being inferred, because the file's
//! dense type table and its length encoding are both places where a reader
//! can be *nearly* right and still desync on the third record.

#[cfg(any(
    feature = "bson",
    feature = "dbf",
    feature = "foxpro",
    feature = "redis-rdb"
))]
use alloc::string::String;
#[cfg(any(feature = "dbf", feature = "foxpro", feature = "redis-rdb"))]
use alloc::string::ToString;
#[cfg(any(feature = "dbf", feature = "foxpro", feature = "redis-rdb"))]
use alloc::vec::Vec;
#[cfg(any(
    feature = "bson",
    feature = "dbf",
    feature = "foxpro",
    feature = "redis-rdb"
))]
use core::fmt::Write as _;

#[cfg(any(feature = "dbf", feature = "foxpro", feature = "redis-rdb"))]
use rgx_core::bail;
#[cfg(any(
    feature = "bson",
    feature = "dbf",
    feature = "foxpro",
    feature = "redis-rdb"
))]
use rgx_core::decline;
#[cfg(any(feature = "bson", feature = "foxpro", feature = "redis-rdb"))]
use rgx_core::Adapter;
#[cfg(any(feature = "dbf", feature = "foxpro"))]
use rgx_core::Field;
#[cfg(any(feature = "bson", feature = "foxpro", feature = "redis-rdb"))]
use rgx_core::Outcome;
#[cfg(any(
    feature = "bson",
    feature = "dbf",
    feature = "foxpro",
    feature = "redis-rdb"
))]
use rgx_core::Result;

// ---------- BSON ----------

#[cfg(feature = "bson")]
const BSON_DOUBLE: u8 = 0x01;
#[cfg(feature = "bson")]
const BSON_STRING: u8 = 0x02;
#[cfg(feature = "bson")]
const BSON_DOC: u8 = 0x03;
#[cfg(feature = "bson")]
const BSON_ARRAY: u8 = 0x04;
#[cfg(feature = "bson")]
const BSON_BINARY: u8 = 0x05;
#[cfg(feature = "bson")]
const BSON_UNDEFINED: u8 = 0x06;
#[cfg(feature = "bson")]
const BSON_OBJECTID: u8 = 0x07;
#[cfg(feature = "bson")]
const BSON_BOOL: u8 = 0x08;
#[cfg(feature = "bson")]
const BSON_DATETIME: u8 = 0x09;
#[cfg(feature = "bson")]
const BSON_NULL: u8 = 0x0A;
#[cfg(feature = "bson")]
const BSON_REGEX: u8 = 0x0B;
#[cfg(feature = "bson")]
const BSON_DBPOINTER: u8 = 0x0C;
#[cfg(feature = "bson")]
const BSON_JAVASCRIPT: u8 = 0x0D;
#[cfg(feature = "bson")]
const BSON_SYMBOL: u8 = 0x0E;
#[cfg(feature = "bson")]
const BSON_SCOPE: u8 = 0x0F;
// 0x10 is int32 and 0x12 is int64. Giving both the same value made the int32
// arm unreachable, and — because BSON_CODE also claimed 0x10 — sent every
// 32-bit field down a `code` arm that does not exist in the spec.
#[cfg(feature = "bson")]
const BSON_INT32: u8 = 0x10;
#[cfg(feature = "bson")]
const BSON_TIMESTAMP: u8 = 0x11;
#[cfg(feature = "bson")]
const BSON_INT64: u8 = 0x12;
#[cfg(feature = "bson")]
const BSON_DECIMAL128: u8 = 0x13;
#[cfg(feature = "bson")]
const BSON_MIN_KEY: u8 = 0xFF;
#[cfg(feature = "bson")]
const BSON_MAX_KEY: u8 = 0x7F;

#[cfg(feature = "bson")]
fn bson_kind(t: u8) -> &'static str {
    match t {
        BSON_DOUBLE => "double",
        BSON_STRING => "string",
        BSON_DOC => "document",
        BSON_ARRAY => "array",
        BSON_BINARY => "binary",
        BSON_UNDEFINED => "undefined",
        BSON_OBJECTID => "objectid",
        BSON_BOOL => "bool",
        BSON_DATETIME => "date",
        BSON_NULL => "null",
        BSON_REGEX => "regex",
        BSON_DBPOINTER => "dbpointer",
        BSON_JAVASCRIPT => "javascript",
        BSON_SYMBOL => "symbol",
        BSON_SCOPE => "code-with-scope",
        BSON_INT32 => "int32",
        BSON_TIMESTAMP => "timestamp",
        BSON_INT64 => "int64",
        BSON_DECIMAL128 => "decimal128",
        BSON_MIN_KEY => "minkey",
        BSON_MAX_KEY => "maxkey",
        _ => "unknown",
    }
}

#[cfg(feature = "bson")]
fn le32(d: &[u8], p: usize) -> Option<u32> {
    let b = d.get(p..p + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(feature = "bson")]
fn cstring(d: &[u8], p: usize) -> Option<(String, usize)> {
    let end = p + d[p..].iter().position(|b| *b == 0)?;
    Some((String::from_utf8_lossy(&d[p..end]).into_owned(), end + 1))
}

/// A value as one printable line: control bytes become escapes, and a
/// value long enough to swamp the listing is clipped. A BSON string field
/// can hold a megabyte, and a listing is not a dump.
#[cfg(any(feature = "bson", feature = "redis-rdb"))]
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(160) + 4);
    for (i, c) in s.chars().enumerate() {
        if i >= 160 {
            out.push_str("...");
            break;
        }
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(feature = "bson")]
pub struct Bson;
#[cfg(feature = "bson")]
impl Adapter for Bson {
    fn name(&self) -> &'static str {
        "bson"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bson"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut out = String::new();
        let mut p = 0usize;
        let mut docs = 0usize;
        while p + 5 <= data.len() {
            let size = le32(data, p).unwrap_or(0) as usize;
            if size < 5 || p + size > data.len() {
                break;
            }
            docs += 1;
            let end = p + size - 1;
            document(data, p + 4, end, "", 0, &mut out)?;
            p += size;
        }
        if docs == 0 {
            decline!("no BSON document (every candidate length runs past the file)");
        }
        let _ = writeln!(out, "documents: {docs}");
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// Walk one document's elements. `end` is the byte before the terminator,
/// so a length that disagrees with the parent's shows up as a short walk
/// rather than as a read past the buffer.
#[cfg(feature = "bson")]
fn document(
    d: &[u8],
    mut p: usize,
    end: usize,
    prefix: &str,
    depth: usize,
    out: &mut String,
) -> Result<()> {
    if depth > 24 {
        return Ok(());
    }
    while p < end {
        let ty = d[p];
        if ty == 0 {
            return Ok(());
        }
        p += 1;
        let Some((name, next)) = cstring(d, p) else {
            return Ok(());
        };
        p = next;
        let path = if prefix.is_empty() {
            name
        } else {
            alloc::format!("{prefix}.{name}")
        };
        match ty {
            BSON_STRING | BSON_SYMBOL | BSON_JAVASCRIPT => {
                let Some(len) = le32(d, p) else { return Ok(()) };
                let start = p + 4;
                let stop = (start + len as usize).min(d.len());
                let text = String::from_utf8_lossy(d.get(start..stop).unwrap_or_default());
                // The declared length counts its own NUL, so the field
                // ends where the string ends -- adding one for the
                // terminator steps over the next element's type byte.
                let _ = writeln!(
                    out,
                    "{path}: {} {}",
                    bson_kind(ty),
                    quote(text.trim_end_matches('\0'))
                );
                p = stop;
            }
            BSON_DOC => {
                let Some(len) = le32(d, p) else { return Ok(()) };
                if len < 5 || p + len as usize > d.len() {
                    return Ok(());
                }
                let _ = writeln!(out, "{path}: document");
                document(d, p + 4, p + len as usize - 1, &path, depth + 1, out)?;
                p += len as usize;
            }
            BSON_ARRAY => {
                let Some(len) = le32(d, p) else { return Ok(()) };
                if len < 5 || p + len as usize > d.len() {
                    return Ok(());
                }
                let _ = writeln!(out, "{path}: array");
                document(d, p + 4, p + len as usize - 1, &path, depth + 1, out)?;
                p += len as usize;
            }
            BSON_BINARY => {
                let Some(len) = le32(d, p) else { return Ok(()) };
                let subtype = d.get(p + 4).copied().unwrap_or(0);
                let stop = (p + 5 + len as usize).min(d.len());
                // 0x02 is the only subtype whose bytes are guaranteed text.
                if subtype == 0x02 {
                    let text = String::from_utf8_lossy(d.get(p + 5..stop).unwrap_or_default());
                    let _ = write!(out, "{path}: binary/utf8 {text}");
                } else {
                    let _ = writeln!(out, "{path}: binary/{len} bytes");
                }
                p = stop;
            }
            BSON_OBJECTID => {
                if let Some(bytes) = d.get(p..p + 12) {
                    let mut hex = String::with_capacity(24);
                    for b in bytes {
                        let _ = write!(hex, "{b:02x}");
                    }
                    let _ = writeln!(out, "{path}: objectid {hex}");
                }
                p += 12;
            }
            BSON_REGEX => {
                let Some((pattern, q)) = cstring(d, p) else {
                    return Ok(());
                };
                let Some((flags, _)) = cstring(d, q) else {
                    return Ok(());
                };
                let _ = writeln!(out, "{path}: regex /{pattern}/{flags}");
                p = q;
                if d[p - 1..].is_empty() {
                    return Ok(());
                }
                // advance past the flags string
                while p < d.len() && d[p] != 0 {
                    p += 1;
                }
                p += 1;
            }
            BSON_DBPOINTER => {
                let len = le32(d, p).unwrap_or(0) as usize;
                let start = p + 4;
                let text = String::from_utf8_lossy(d.get(start..start + len).unwrap_or_default());
                let _ = writeln!(out, "{path}: dbpointer {text}");
                p = start + len + 12;
            }
            BSON_BOOL | BSON_NULL | BSON_UNDEFINED | BSON_MIN_KEY | BSON_MAX_KEY => {
                let v = if ty == BSON_BOOL {
                    d.get(p).map(|b| if *b == 0 { "false" } else { "true" })
                } else {
                    Some("null")
                };
                let _ = writeln!(out, "{path}: {}", v.unwrap_or("null"));
                p += 1;
            }
            BSON_INT32 => {
                let v = le32(d, p).map(|x| x as i64).unwrap_or(0);
                let _ = writeln!(out, "{path}: {} {v}", bson_kind(BSON_INT32));
                p += 4;
            }
            BSON_INT64 | BSON_DATETIME | BSON_TIMESTAMP => {
                let v = d
                    .get(p..p + 8)
                    .map(|b| i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
                let raw = d
                    .get(p..p + 8)
                    .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
                match ty {
                    BSON_DATETIME => {
                        let ms = v.unwrap_or(0);
                        let _ = writeln!(out, "{path}: date {ms} ms since the epoch");
                    }
                    BSON_TIMESTAMP => {
                        let secs = (raw.unwrap_or(0) >> 32) as u32;
                        let inc = (raw.unwrap_or(0) & 0xFFFF_FFFF) as u32;
                        let _ = writeln!(out, "{path}: timestamp {inc}/{secs}");
                    }
                    _ => {
                        let _ = writeln!(out, "{path}: {} {}", bson_kind(ty), v.unwrap_or(0));
                    }
                }
                p += 8;
            }
            BSON_DOUBLE => {
                let bits = d
                    .get(p..p + 8)
                    .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                    .unwrap_or(0);
                let _ = writeln!(out, "{path}: double {}", f64::from_bits(bits));
                p += 8;
            }
            BSON_DECIMAL128 => {
                // 16 bytes of BCD with a 4-byte exponent/sign prefix; the
                // significand is worth printing, the decimal point is not
                // reconstructed.
                let bytes = d.get(p..p + 16).unwrap_or(&[0u8; 16]);
                let mut hex = String::with_capacity(32);
                for b in bytes {
                    let _ = write!(hex, "{b:02x}");
                }
                let _ = writeln!(out, "{path}: decimal128 {hex}");
                p += 16;
            }
            BSON_SCOPE => {
                // code-with-scope: total length, then a string, then a
                // document. The header is enough to name it.
                let len = le32(d, p).unwrap_or(0);
                let _ = writeln!(out, "{path}: scope {len} bytes");
                p += len as usize;
            }
            _ => return Ok(()),
        }
        if p > d.len() {
            return Ok(());
        }
    }
    Ok(())
}

// ---------- Redis RDB ----------
//
// Every constant below follows Redis `src/rdb.h`. The type bytes
// are the part a reader cannot infer: they are dense, they skip 8, and one
// off-by-one makes a `SET_LISTPACK` (20) read as a `STREAM_LISTPACKS_3` (21)
// — which still parses, so the desync only surfaces as nonsense keys three
// records later.

#[cfg(feature = "redis-rdb")]
const RDB_STRING: u8 = 0;
#[cfg(feature = "redis-rdb")]
const RDB_LIST: u8 = 1;
#[cfg(feature = "redis-rdb")]
const RDB_SET: u8 = 2;
#[cfg(feature = "redis-rdb")]
const RDB_ZSET: u8 = 3;
#[cfg(feature = "redis-rdb")]
const RDB_HASH: u8 = 4;
#[cfg(feature = "redis-rdb")]
const RDB_ZSET_2: u8 = 5;
#[cfg(feature = "redis-rdb")]
const RDB_MODULE_PRE_GA: u8 = 6;
#[cfg(feature = "redis-rdb")]
const RDB_MODULE_2: u8 = 7;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_ZIPMAP: u8 = 9;
#[cfg(feature = "redis-rdb")]
const RDB_LIST_ZIPLIST: u8 = 10;
#[cfg(feature = "redis-rdb")]
const RDB_SET_INTSET: u8 = 11;
#[cfg(feature = "redis-rdb")]
const RDB_ZSET_ZIPLIST: u8 = 12;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_ZIPLIST: u8 = 13;
#[cfg(feature = "redis-rdb")]
const RDB_LIST_QUICKLIST: u8 = 14;
#[cfg(feature = "redis-rdb")]
const RDB_STREAM_LISTPACKS: u8 = 15;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_LISTPACK: u8 = 16;
#[cfg(feature = "redis-rdb")]
const RDB_ZSET_LISTPACK: u8 = 17;
#[cfg(feature = "redis-rdb")]
const RDB_LIST_QUICKLIST_2: u8 = 18;
#[cfg(feature = "redis-rdb")]
const RDB_STREAM_LISTPACKS_2: u8 = 19;
#[cfg(feature = "redis-rdb")]
const RDB_SET_LISTPACK: u8 = 20;
#[cfg(feature = "redis-rdb")]
const RDB_STREAM_LISTPACKS_3: u8 = 21;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_METADATA_PRE_GA: u8 = 22;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_LISTPACK_EX_PRE_GA: u8 = 23;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_METADATA: u8 = 24;
#[cfg(feature = "redis-rdb")]
const RDB_HASH_LISTPACK_EX: u8 = 25;
#[cfg(feature = "redis-rdb")]
const RDB_STREAM_LISTPACKS_4: u8 = 26;
#[cfg(feature = "redis-rdb")]
const RDB_ARRAY: u8 = 28;
#[cfg(feature = "redis-rdb")]
const RDB_BITMAP: u8 = 33;

/// `rdbIsObjectType`: the dense range 0..=7, a hole at 8, then 9 upward.
#[cfg(feature = "redis-rdb")]
fn rdb_is_object_type(t: u8) -> bool {
    t <= 7 || (9..=33).contains(&t)
}

// Opcodes. Everything at or above 241 is a per-key or per-file attribute
// rather than an object type.
#[cfg(feature = "redis-rdb")]
const OP_FUNCTION2: u8 = 245;
#[cfg(feature = "redis-rdb")]
const OP_FUNCTION_PRE_GA: u8 = 246;
#[cfg(feature = "redis-rdb")]
const OP_MODULE_AUX: u8 = 247;
#[cfg(feature = "redis-rdb")]
const OP_IDLE: u8 = 248;
#[cfg(feature = "redis-rdb")]
const OP_FREQ: u8 = 249;
#[cfg(feature = "redis-rdb")]
const OP_AUX: u8 = 250;
#[cfg(feature = "redis-rdb")]
const OP_RESIZEDB: u8 = 251;
#[cfg(feature = "redis-rdb")]
const OP_EXPIRETIME_MS: u8 = 252;
#[cfg(feature = "redis-rdb")]
const OP_EXPIRETIME: u8 = 253;
#[cfg(feature = "redis-rdb")]
const OP_SELECTDB: u8 = 254;
#[cfg(feature = "redis-rdb")]
const OP_EOF: u8 = 255;

/// Quicklist node containers (`quicklist.h`).
#[cfg(feature = "redis-rdb")]
const QL_NODE_NONE: u64 = 1;
#[cfg(feature = "redis-rdb")]
const QL_NODE_PLAIN: u64 = 2;
#[cfg(feature = "redis-rdb")]
const QL_NODE_PACKED: u64 = 3;
#[cfg(feature = "redis-rdb")]
const QL_NODE_COMPRESSED: u64 = 4;

/// Special *string* encodings (`RDB_ENC_*`): a length whose top two bits are
/// set is not a length, it names one of these.
#[cfg(feature = "redis-rdb")]
const RDB_ENC_INT8: u8 = 0;
#[cfg(feature = "redis-rdb")]
const RDB_ENC_INT16: u8 = 1;
#[cfg(feature = "redis-rdb")]
const RDB_ENC_INT32: u8 = 2;
#[cfg(feature = "redis-rdb")]
const RDB_ENC_LZF: u8 = 3;

/// The two whole-byte length prefixes. These are compared for *equality*,
/// not by their top bits: `0b10|001100` is not a 32-bit length, it is
/// corruption.
#[cfg(feature = "redis-rdb")]
const RDB_32BITLEN: u8 = 0x80;
#[cfg(feature = "redis-rdb")]
const RDB_64BITLEN: u8 = 0x81;

/// The highest RDB version this reader claims. `RDB_VERSION` is 16 upstream.
#[cfg(feature = "redis-rdb")]
const RDB_MAX_VERSION: u32 = 16;

#[cfg(feature = "redis-rdb")]
fn rdb_kind(t: u8) -> &'static str {
    match t {
        RDB_STRING => "string",
        RDB_LIST | RDB_LIST_ZIPLIST | RDB_LIST_QUICKLIST | RDB_LIST_QUICKLIST_2 => "list",
        RDB_SET | RDB_SET_INTSET | RDB_SET_LISTPACK => "set",
        RDB_ZSET | RDB_ZSET_2 | RDB_ZSET_ZIPLIST | RDB_ZSET_LISTPACK => "zset",
        RDB_ARRAY => "array",
        RDB_BITMAP => "bitmap",
        RDB_HASH | RDB_HASH_ZIPMAP | RDB_HASH_ZIPLIST | RDB_HASH_LISTPACK
        | RDB_HASH_LISTPACK_EX => "hash",
        RDB_HASH_METADATA | RDB_HASH_METADATA_PRE_GA | RDB_HASH_LISTPACK_EX_PRE_GA => {
            "hash-with-ttl"
        }
        RDB_MODULE_PRE_GA | RDB_MODULE_2 => "module",
        RDB_STREAM_LISTPACKS
        | RDB_STREAM_LISTPACKS_2
        | RDB_STREAM_LISTPACKS_3
        | RDB_STREAM_LISTPACKS_4 => "stream",
        _ => "unknown",
    }
}

/// `rdbLoadLenByRef`, followed. The result is either a plain length or a
/// special-encoding kind, and those two are not interchangeable: `0xC3` is
/// LZF, not the length 3, and reading it as a length walks the stream into
/// the middle of a payload.
///
/// The 64-bit form is why this cannot be a `first >> 6` switch on `2`: that
/// branch would swallow `0x80` through `0xBF` as 32-bit lengths, when only
/// `0x80` and `0x81` are defined there.
#[cfg(feature = "redis-rdb")]
fn rdb_len(d: &[u8], p: usize) -> Option<RdbLen> {
    let first = *d.get(p)?;
    match first >> 6 {
        0 => Some(RdbLen::Len((first & 0x3F) as u64, p + 1)),
        1 => {
            let b = *d.get(p + 1)?;
            Some(RdbLen::Len(
                (((first as u64) & 0x3F) << 8) | b as u64,
                p + 2,
            ))
        }
        _ => {
            if first == RDB_32BITLEN {
                let b = d.get(p + 1..p + 5)?;
                Some(RdbLen::Len(
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64,
                    p + 5,
                ))
            } else if first == RDB_64BITLEN {
                let b = d.get(p + 1..p + 9)?;
                Some(RdbLen::Len(
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    p + 9,
                ))
            } else if first & 0xC0 == 0xC0 {
                Some(RdbLen::Encoded(first & 0x3F, p + 1))
            } else {
                // `10|xxxxxx` other than 0x80/0x81: Redis calls this corrupt.
                None
            }
        }
    }
}

/// A decoded length, and the two things a length can mean. Keeping them in
/// one type is what stops a caller from treating an encoding kind as a byte
/// count.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg(feature = "redis-rdb")]
enum RdbLen {
    Len(u64, usize),
    Encoded(u8, usize),
}

#[cfg(feature = "redis-rdb")]
impl RdbLen {
    /// The byte count — for an encoded length this is the *kind*, which is
    /// why a caller that wants a count must go through `count()`.
    fn value(self) -> u64 {
        match self {
            RdbLen::Len(v, _) => v,
            RdbLen::Encoded(k, _) => k as u64,
        }
    }
    fn next(self) -> usize {
        match self {
            RdbLen::Len(_, n) | RdbLen::Encoded(_, n) => n,
        }
    }
    fn is_encoded(self) -> bool {
        matches!(self, RdbLen::Encoded(..))
    }
}

#[cfg(feature = "redis-rdb")]
pub struct RedisRdb;
#[cfg(feature = "redis-rdb")]
impl Adapter for RedisRdb {
    fn name(&self) -> &'static str {
        "redis-rdb"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["rdb"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if data.len() < 9 || &data[..5] != b"REDIS" {
            decline!("not a Redis RDB file (bad magic)");
        }
        let w = walk_rdb(data)?;
        if w.keys == 0 && !w.text.contains("select db") {
            bail!("RDB file holds no keyspace");
        }
        Ok(Outcome::Text(w.text.into_bytes()))
    }
}

/// What one RDB walk produced.
#[cfg(feature = "redis-rdb")]
pub(crate) struct RdbWalk {
    pub text: String,
    pub keys: usize,
    /// Offset just past the EOF opcode, and only when the walk actually
    /// reached it. Every early return leaves it `None`, because a walk that
    /// gave up on truncation or on a shape it cannot decode says nothing about
    /// where the section ends -- and the AOF reader needs a real boundary to
    /// find the command log that a preamble sits in front of.
    #[cfg(feature = "redis-aof")]
    pub eof_at: Option<usize>,
}

/// Walk an RDB section. The caller has already checked the `REDIS` magic;
/// this validates the version and renders the keyspace.
#[cfg(feature = "redis-rdb")]
pub(crate) fn walk_rdb(data: &[u8]) -> Result<RdbWalk> {
    let version: u32 = String::from_utf8_lossy(data.get(5..9).unwrap_or_default())
        .trim()
        .parse()
        .unwrap_or(0);
    if version == 0 || version > RDB_MAX_VERSION {
        bail!("unsupported RDB version {version}");
    }
    let mut r = Rdb {
        d: data,
        ver: version,
        p: 9,
        out: String::new(),
        db: 0,
        keys: 0,
        done: false,
        #[cfg(feature = "redis-aof")]
        eof_at: None,
    };
    r.run();
    Ok(RdbWalk {
        text: r.out,
        keys: r.keys,
        #[cfg(feature = "redis-aof")]
        eof_at: r.eof_at,
    })
}

#[cfg(feature = "redis-rdb")]
struct Rdb<'a> {
    d: &'a [u8],
    ver: u32,
    p: usize,
    out: String,
    db: usize,
    keys: usize,
    /// Set the moment a shape cannot be walked. A walk that continues past
    /// it would print records that were never there.
    done: bool,
    /// Offset just past the EOF opcode, set only on the opcode that ends a
    /// section. See [`RdbWalk::eof_at`].
    #[cfg(feature = "redis-aof")]
    eof_at: Option<usize>,
}

#[cfg(feature = "redis-rdb")]
impl<'a> Rdb<'a> {
    fn note(&mut self, s: &str) {
        let _ = writeln!(self.out, "{s}");
    }

    fn bail_at(&mut self, why: &str) {
        let at = self.p;
        self.done = true;
        let _ = writeln!(self.out, "stopped at offset {at}: {why}");
    }

    fn run(&mut self) {
        let _ = writeln!(self.out, "REDIS rdb version {}", self.ver);
        let mut guard = 0usize;
        while self.p < self.d.len() {
            guard += 1;
            if guard > 2_000_000 {
                self.note("stopped: record limit reached");
                return;
            }
            let Some(op) = self.byte() else { return };
            match op {
                OP_EOF => {
                    let _ = writeln!(self.out, "eof after {} keys", self.keys);
                    // `byte` already advanced past the opcode, so the cursor is
                    // the first byte after it -- the start of an optional
                    // checksum, and after that of a command log.
                    #[cfg(feature = "redis-aof")]
                    {
                        self.eof_at = Some(self.p);
                    }
                    return;
                }
                OP_SELECTDB => {
                    let Some(n) = self.count() else { return };
                    self.db = n as usize;
                    let _ = writeln!(self.out, "select db {}", self.db);
                }
                OP_RESIZEDB => {
                    let Some(size) = self.count() else { return };
                    let Some(_expires) = self.count() else { return };
                    let _ = writeln!(self.out, "resize db {} to {size}", self.db);
                }
                OP_AUX => {
                    let Some((k, q)) = self.string() else { return };
                    let Some((v, r)) = self.string_at(q) else {
                        return;
                    };
                    self.p = r;
                    let _ = writeln!(self.out, "aux {k}: {}", quote(&v));
                }
                OP_IDLE => {
                    let Some(n) = self.count() else { return };
                    let _ = writeln!(self.out, "idle {n}");
                }
                OP_FREQ => {
                    let Some(f) = self.byte() else { return };
                    let _ = writeln!(self.out, "freq {f}");
                }
                OP_EXPIRETIME => {
                    // seconds, four raw little-endian bytes
                    let Some(b) = self.d.get(self.p..self.p + 4) else {
                        self.bail_at("truncated expire time");
                        return;
                    };
                    let secs = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                    self.p += 4;
                    let _ = writeln!(self.out, "expires in {secs}s");
                }
                OP_EXPIRETIME_MS => {
                    // eight raw little-endian bytes from RDB 3 on
                    let Some(b) = self.d.get(self.p..self.p + 8) else {
                        self.bail_at("truncated expire time");
                        return;
                    };
                    let ms = i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
                    self.p += 8;
                    let _ = writeln!(self.out, "expires at {ms} ms");
                }
                OP_MODULE_AUX => {
                    let Some(id) = self.count() else { return };
                    let Some(_when) = self.count() else { return };
                    let _ = writeln!(self.out, "module aux id {id}");
                    // The payload belongs to the module that owns the id, and
                    // the terminating opcode is not a length — continuing would
                    // walk into it.
                    self.bail_at("module aux payload is owned by the module that wrote it");
                    return;
                }
                OP_FUNCTION2 => {
                    if let Some((name, _)) = self.string() {
                        let _ = writeln!(self.out, "function library: {}", quote(&name));
                    } else {
                        return;
                    }
                    self.bail_at("function library body follows its name");
                    return;
                }
                OP_FUNCTION_PRE_GA => {
                    self.bail_at("pre-release function format");
                    return;
                }
                op if !rdb_is_object_type(op) => {
                    self.bail_at("not an object type");
                    return;
                }
                op => self.key_value(op),
            }
            if self.done {
                return;
            }
        }
    }

    // ---- primitives ----

    fn byte(&mut self) -> Option<u8> {
        let b = self.d.get(self.p).copied();
        if b.is_some() {
            self.p += 1;
        }
        b
    }

    fn len(&mut self) -> Option<RdbLen> {
        let l = rdb_len(self.d, self.p)?;
        self.p = l.next();
        Some(l)
    }

    /// A count or a byte count: never an encoding kind. Redis refuses those
    /// positions outright, and so does this.
    fn count(&mut self) -> Option<u64> {
        let l = self.len()?;
        if l.is_encoded() {
            self.bail_at("an encoded length where a count is required");
            return None;
        }
        Some(l.value())
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.d.get(self.p..end)?;
        self.p = end;
        Some(s)
    }

    /// `rdbGenericLoadStringObject`: a length, and then either the bytes or
    /// one of the four special encodings.
    fn string(&mut self) -> Option<(String, usize)> {
        let at = self.p;
        let (text, next) = self.string_at(at)?;
        self.p = next;
        Some((text, next))
    }

    fn string_at(&mut self, at: usize) -> Option<(String, usize)> {
        let mut p = at;
        let l = rdb_len(self.d, p)?;
        p = l.next();
        if let RdbLen::Encoded(kind, _) = l {
            match kind {
                RDB_ENC_INT8 => {
                    let b = *self.d.get(p)?;
                    p += 1;
                    return Some(((b as i8).to_string(), p));
                }
                RDB_ENC_INT16 => {
                    let b = self.d.get(p..p + 2)?;
                    p += 2;
                    return Some((i16::from_le_bytes([b[0], b[1]]).to_string(), p));
                }
                RDB_ENC_INT32 => {
                    let b = self.d.get(p..p + 4)?;
                    p += 4;
                    return Some((i32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string(), p));
                }
                RDB_ENC_LZF => {
                    // rdbSaveLzfBlob: clen, ulen, then the payload.
                    let cl = rdb_len(self.d, p)?;
                    if cl.is_encoded() {
                        return None;
                    }
                    p = cl.next();
                    let ul = rdb_len(self.d, p)?;
                    if ul.is_encoded() {
                        return None;
                    }
                    p = ul.next();
                    let clen = cl.value() as usize;
                    let ulen = ul.value() as usize;
                    let body = self.d.get(p..p.checked_add(clen)?)?;
                    p += clen;
                    return Some((lzf_to_string(body, ulen), p));
                }
                _ => return None,
            }
        }
        let n = l.value() as usize;
        let body = self.d.get(p..p.checked_add(n)?)?;
        p += n;
        Some((String::from_utf8_lossy(body).into_owned(), p))
    }

    /// A `ZSET_2` score. From RDB 8 on it is a raw little-endian binary64;
    /// before that it was a length-prefixed decimal string with 253/254/255
    /// standing for nan/+inf/-inf. Getting this wrong turns every score into
    /// a plausible-looking float.
    fn score(&mut self) -> Option<f64> {
        if self.ver >= 8 {
            let b = self.d.get(self.p..self.p + 8)?;
            self.p += 8;
            return Some(f64::from_bits(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ])));
        }
        let len = *self.d.get(self.p)?;
        self.p += 1;
        match len {
            253 => return Some(f64::NAN),
            254 => return Some(f64::INFINITY),
            255 => return Some(f64::NEG_INFINITY),
            _ => {}
        }
        let body = self.d.get(self.p..self.p.checked_add(len as usize)?)?;
        self.p += len as usize;
        core::str::from_utf8(body)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
    }

    // ---- records ----

    fn key_value(&mut self, ty: u8) {
        let Some((key, after_key)) = self.string() else {
            return;
        };
        self.keys += 1;
        let db = self.db;
        let kind = rdb_kind(ty);
        match ty {
            RDB_STRING => {
                let Some((v, _)) = self.string() else {
                    self.bail_at("string value did not decode");
                    return;
                };
                let _ = writeln!(self.out, "key[{db}] {key}: string {}", quote(&v));
            }
            RDB_LIST | RDB_SET | RDB_ARRAY => {
                let Some(count) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: {kind} ({count} entries)");
                for i in 0..count {
                    let Some((v, _)) = self.string() else {
                        self.bail_at("entry did not decode");
                        return;
                    };
                    let _ = writeln!(self.out, "  [{}] {}", i, quote(&v));
                }
            }
            RDB_ZSET | RDB_ZSET_2 => {
                let Some(count) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: {kind} ({count} entries)");
                for _ in 0..count {
                    let Some((member, _)) = self.string() else {
                        self.bail_at("member did not decode");
                        return;
                    };
                    let Some(score) = self.score() else {
                        self.bail_at("score did not decode");
                        return;
                    };
                    let _ = writeln!(self.out, "  {member} -> {score}");
                }
            }
            RDB_HASH | RDB_HASH_ZIPMAP => {
                let Some(count) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: {kind} ({count} entries)");
                for _ in 0..count {
                    let Some((field, _)) = self.string() else {
                        self.bail_at("field did not decode");
                        return;
                    };
                    let Some((v, _)) = self.string() else {
                        self.bail_at("value did not decode");
                        return;
                    };
                    let _ = writeln!(self.out, "  {field}: {}", quote(&v));
                }
            }
            // The compact encodings are one opaque blob: their internal list
            // counts are not RDB lengths, so reading a count here and then
            // that many "strings" walks into the middle of a listpack.
            RDB_LIST_ZIPLIST | RDB_SET_INTSET | RDB_ZSET_ZIPLIST | RDB_HASH_ZIPLIST
            | RDB_HASH_LISTPACK | RDB_ZSET_LISTPACK | RDB_SET_LISTPACK => {
                let Some((v, _)) = self.string() else {
                    self.bail_at("packed blob did not decode");
                    return;
                };
                let _ = writeln!(
                    self.out,
                    "key[{db}] {key}: {kind} ({}-packed)",
                    quote(&printable_share(&v))
                );
                let _ = writeln!(self.out, "  {}", quote(&v));
            }
            RDB_LIST_QUICKLIST => {
                let Some(nodes) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: list ({nodes} nodes)");
                for n in 0..nodes {
                    let Some((v, _)) = self.string() else {
                        self.bail_at("quicklist node did not decode");
                        return;
                    };
                    let _ = writeln!(self.out, "  node {n}: {}", quote(&v));
                }
            }
            RDB_LIST_QUICKLIST_2 => {
                let Some(nodes) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: list ({nodes} nodes)");
                for n in 0..nodes {
                    let Some(container) = self.count() else {
                        return;
                    };
                    match container {
                        QL_NODE_PLAIN | QL_NODE_PACKED | QL_NODE_NONE => {
                            let Some((v, _)) = self.string() else {
                                self.bail_at("quicklist node did not decode");
                                return;
                            };
                            let _ = writeln!(self.out, "  node {n}: {}", quote(&v));
                        }
                        QL_NODE_COMPRESSED => {
                            let Some((v, _)) = self.lzf_blob() else {
                                self.bail_at("compressed quicklist node did not decode");
                                return;
                            };
                            let _ = writeln!(self.out, "  node {n} (lzf): {}", quote(&v));
                        }
                        other => {
                            self.bail_at(&alloc::format!("unknown quicklist container {other}"));
                            return;
                        }
                    }
                }
            }
            RDB_HASH_METADATA
            | RDB_HASH_METADATA_PRE_GA
            | RDB_HASH_LISTPACK_EX
            | RDB_HASH_LISTPACK_EX_PRE_GA => {
                // A minimum TTL precedes the field count, and a per-field TTL
                // follows every field. Both are plain lengths.
                if (ty == RDB_HASH_METADATA || ty == RDB_HASH_LISTPACK_EX) && self.count().is_none()
                {
                    return;
                }
                let Some(count) = self.count() else { return };
                let _ = writeln!(self.out, "key[{db}] {key}: {kind} ({count} entries)");
                for _ in 0..count {
                    let Some((field, _)) = self.string() else {
                        self.bail_at("field did not decode");
                        return;
                    };
                    let Some((v, _)) = self.string() else {
                        self.bail_at("value did not decode");
                        return;
                    };
                    let _ = writeln!(self.out, "  {field}: {}", quote(&v));
                }
            }
            other => {
                let _ = writeln!(
                    self.out,
                    "key[{db}] {key}: {} (record not decoded by this build)",
                    rdb_kind(other)
                );
                let how = match other {
                    RDB_MODULE_PRE_GA | RDB_MODULE_2 => {
                        "a module payload is opaque to a reader that does not know the module"
                    }
                    RDB_STREAM_LISTPACKS
                    | RDB_STREAM_LISTPACKS_2
                    | RDB_STREAM_LISTPACKS_3
                    | RDB_STREAM_LISTPACKS_4 => "a stream carries a radix tree and a PEL",
                    RDB_BITMAP => "a bitmap is a roaring64 blob",
                    _ => "the layout is newer than this reader",
                };
                self.bail_at(how);
                return;
            }
        }
        let _ = after_key;
    }

    /// `rdbSaveLzfBlob` outside a string: compressed length, uncompressed
    /// length, payload.
    fn lzf_blob(&mut self) -> Option<(String, usize)> {
        let cl = self.count()?;
        let ul = self.count()?;
        let body = self.bytes(cl as usize)?;
        Some((lzf_to_string(body, ul as usize), self.p))
    }
}

/// liblzf's decompressor, written from `lzfP.h`, because Redis vendors it
/// rather than depending on it and there is no decoder in this tree to reuse.
/// The bounds are load-bearing: a corrupt `dump.rdb` must not produce a read
/// past either the input or the output.
#[cfg(feature = "redis-rdb")]
fn lzf_decompress(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut ip = 0usize;
    let mut op = 0usize;
    while ip < input.len() {
        let ctrl = input[ip] as usize;
        ip += 1;
        if ctrl < (1 << 5) {
            // A literal run of ctrl+1 bytes.
            let n = ctrl + 1;
            let body = input.get(ip..ip.checked_add(n)?)?;
            let dst = out.get_mut(op..op.checked_add(n)?)?;
            dst.copy_from_slice(body);
            ip += n;
            op += n;
        } else {
            // 5 bits of length above, 13 bits of offset split across the rest
            // of this byte and the next.
            let mut len = ctrl >> 5;
            let off = ((ctrl & 0x1f) << 8) + (*input.get(ip)? as usize) + 1;
            ip += 1;
            len += 2;
            if len == 7 {
                len += *input.get(ip)? as usize;
                ip += 1;
            }
            if off == 0 || off > op {
                return None;
            }
            let end = op.checked_add(len)?;
            if end > out.len() {
                return None;
            }
            // Overlapping is the point: offset 1 is a run byte, and each
            // byte is copied from what the previous iteration just wrote.
            for i in 0..len {
                out[op + i] = out[op + i - off];
            }
            op = end;
        }
    }
    Some(op)
}

#[cfg(feature = "redis-rdb")]
fn lzf_to_string(body: &[u8], ulen: usize) -> String {
    // The declared uncompressed length is what Redis allocates; cap it so a
    // length claiming four gigabytes cannot ask for four gigabytes.
    let want = ulen.min(1 << 22);
    let mut out: Vec<u8> = vec![0; want];
    match lzf_decompress(body, &mut out) {
        Some(n) => {
            out.truncate(n);
            String::from_utf8_lossy(&out).into_owned()
        }
        None => {
            // Redis treats a bad LZF stream as corruption. Say so rather than
            // returning the compressed bytes as if they were the value.
            format!("[lzf payload of {ulen} bytes did not decompress]")
        }
    }
}

/// How much of a packed blob is printable, which is the only honest way to
/// summarise a listpack: its fields are counted in its own encoding.
#[cfg(feature = "redis-rdb")]
fn printable_share(v: &str) -> String {
    let printable = v.bytes().filter(|b| (0x20..0x7f).contains(b)).count();
    let total = v.len().max(1);
    alloc::format!("{}% text", printable * 100 / total)
}

// ---------- dBase and Visual FoxPro ----------

/// One column of a dBase table.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
pub(crate) struct DbfField {
    /// The name of the column: the first 11 bytes of the descriptor,
    /// NUL-padded.
    pub name: String,
    /// The type byte of the descriptor. `M` marks a memo field: its four
    /// bytes are the number of the block its text lives in, and the text
    /// itself is in the memo file beside the table.
    pub kind: u8,
    /// The width of the column in a record.
    pub len: usize,
    /// Where the column starts in a record, past the delete flag.
    pub offset: usize,
}

/// The field descriptors of a DBF header: every column, in file order.
///
/// A DBF header is a run of 32-byte descriptors that ends with the `0x0D`
/// terminator; the name is the first 11 bytes of a descriptor, NUL-padded,
/// and the twelfth byte is the type of the column.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
pub(crate) fn dbf_fields(data: &[u8], header_size: usize) -> Vec<DbfField> {
    let mut fields = Vec::new();
    let mut p = 32usize;
    let mut offset = 1usize; // a record starts with its delete flag
    while p + 32 <= header_size && data[p] != 0x0d {
        let name = String::from_utf8_lossy(&data[p..p + 11])
            .trim_matches(char::from(0))
            .to_string();
        let len = data[p + 16] as usize;
        fields.push(DbfField {
            name,
            kind: data[p + 11],
            len,
            offset,
        });
        offset += len;
        p += 32;
    }
    fields
}

/// A dBase table as TSV: the column names, then one row per record.
///
/// A memo field holds the number of the block its text lives in, so a
/// table read without its memo file shows the number where the sentence
/// is, and a table read with one shows the text.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
pub(crate) fn dbf_dump(data: &[u8], memo: Option<&MemoFile>) -> Result<String> {
    if data.len() < 32 {
        decline!("too small for DBF");
    }
    let version = data[0];
    // dBase/FoxPro/Visual FoxPro versions span 0x02..0x8b plus 0xf5..0xfb
    // (FoxPro 2.x, VFP with DBC, etc.). An allowlist rejects real
    // FoxPro-era files, so accept any non-zero version byte and let the
    // structural validation below decide.
    if version == 0x00 {
        decline!("not a DBF file (version byte is zero)");
    }
    let n_records = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let header_size = u16::from_le_bytes([data[8], data[9]]) as usize;
    let record_size = u16::from_le_bytes([data[10], data[11]]) as usize;
    if header_size < 33 || header_size > data.len() || record_size < 1 {
        bail!("bad DBF header sizes");
    }
    let fields = dbf_fields(data, header_size);
    let mut out = String::new();
    // Header byte 28 carries three flags: 0x01 a structural .cdx, 0x02 an
    // associated .fpt memo, 0x04 "this file is a .dbc". Naming it costs
    // one line and is the only thing that tells a reader the rows below
    // are a container's metadata rather than a table's data.
    let table_flags = data[28];
    if table_flags & 0x04 != 0 {
        out.push_str("visual foxpro database container (header byte 28, bit 3)\n");
    }
    match memo {
        Some(file) => {
            let _ = writeln!(out, "{}", file.headline());
        }
        None if table_flags & 0x02 != 0 => {
            out.push_str("has an associated .fpt memo file; memo fields are block numbers here\n");
        }
        None => {}
    }
    out.push_str(
        &fields
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>()
            .join("\t"),
    );
    out.push('\n');
    let mut rec = header_size;
    let mut emitted = 0usize;
    let mut line = String::new();
    while emitted < n_records.min(1_000_000) && rec + record_size <= data.len() {
        if data[rec] == 0x1a {
            break;
        } // EOF marker
        if data[rec] != b'*' {
            // not deleted
            line.clear();
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    line.push('\t');
                }
                // Both ends of the slice have to be clamped, not just the
                // end. A field whose declared length runs past the
                // record -- a malformed table, which a `.dbc` can be --
                // puts `rec + off` beyond `end`, and a range whose start
                // is past its end panics on the slice rather than
                // yielding the empty field it should.
                let start = rec + f.offset;
                let limit = rec + record_size;
                let end = start.saturating_add(f.len).min(limit);
                if start >= end {
                    continue;
                }
                let field = &data[start..end];
                // A memo field is a block number, not text, and the text
                // is in the memo file beside the table. A Visual FoxPro
                // memo field is four bytes: the number of the block, least
                // significant byte first. The block number zero is the
                // header record, which is what an empty memo field holds.
                if f.kind == b'M' && f.len == 4 {
                    let block = u32::from_le_bytes([field[0], field[1], field[2], field[3]]);
                    match memo {
                        Some(file) if block != 0 => match file.block(block) {
                            Some(text) => line.push_str(&memo_text(text)),
                            None => {
                                let _ = write!(line, "block {block}");
                            }
                        },
                        // Without the memo file the table has nothing but
                        // the number to give, and the number is what the
                        // row carries -- the bytes, as they always were.
                        _ => {
                            let field = String::from_utf8_lossy(field);
                            line.push_str(field.trim_matches(char::from(0)).trim_end());
                        }
                    }
                    continue;
                }
                let field = String::from_utf8_lossy(field);
                line.push_str(field.trim_matches(char::from(0)).trim_end());
            }
            out.push_str(&line);
            out.push('\n');
            emitted += 1;
        }
        rec += record_size;
    }
    if emitted == 0 {
        bail!("DBF contains no records");
    }
    Ok(out)
}

/// The facts the `--filter` asks about: the name of every column.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
pub(crate) fn dbf_facts(data: &[u8]) -> Vec<Field> {
    let mut facts = Vec::new();
    // The same checks the dump makes, minus the ones that are about the
    // records: a fact is about the header, and a header that does not fit
    // the file is not a header.
    if data.len() < 32 || data[0] == 0x00 {
        return facts;
    }
    let header_size = u16::from_le_bytes([data[8], data[9]]) as usize;
    if header_size < 33 || header_size > data.len() {
        return facts;
    }
    for f in dbf_fields(data, header_size) {
        if !f.name.is_empty() {
            facts.push(Field::new("table.column", &f.name));
        }
    }
    facts
}

/// A Visual FoxPro memo file: the `.fpt` beside a table, the `.dct` beside
/// a database container.
///
/// The file is a 512-byte header record and then fixed-size blocks. The
/// header says the number of the next free block and the size of a block,
/// both most significant byte first. A block sits at `number * size` bytes
/// into the file, so the header record itself takes the first `512 / size`
/// of them, and a block is an eight-byte header -- a signature and the
/// length of the text -- followed by the text.
///
/// A memo longer than a block runs into the next one, so the length in the
/// header is the length of the text and not the length of the block.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
pub(crate) struct MemoFile<'a> {
    /// The name of the file, for the report.
    pub name: String,
    data: &'a [u8],
    block_size: usize,
    next_free: u32,
}

#[cfg(any(feature = "dbf", feature = "foxpro"))]
impl<'a> MemoFile<'a> {
    /// The memo file in `data`, if it is one.
    #[cfg(feature = "foxpro")]
    pub(crate) fn open(name: &str, data: &'a [u8]) -> Option<Self> {
        if data.len() < 512 {
            return None;
        }
        let next_free = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let block_size = u16::from_be_bytes([data[6], data[7]]) as usize;
        // The header record has to be a whole number of blocks, or the
        // number of the first memo is not the one the file's own
        // arithmetic gives.
        if block_size < 8 || 512 % block_size != 0 {
            return None;
        }
        if next_free == 0 {
            return None;
        }
        Some(MemoFile {
            name: name.to_string(),
            data,
            block_size,
            next_free,
        })
    }

    /// The number of the first block that holds a memo: the header record
    /// takes the first `512 / block_size` blocks of the file.
    pub(crate) fn first_block(&self) -> u32 {
        (512 / self.block_size) as u32
    }

    /// The text of block `n`, if the file has one.
    ///
    /// A block's signature is 1 for text and 0 for a picture; a block with
    /// any other signature is not a block, which is how the space a file
    /// has left over is told from the memos before it.
    pub(crate) fn block(&self, n: u32) -> Option<&'a [u8]> {
        if n < self.first_block() {
            return None;
        }
        let off = n as usize * self.block_size;
        let head = self.data.get(off..off + 8)?;
        let signature = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if signature > 1 {
            return None;
        }
        let len = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
        let start = off + 8;
        let end = start.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        Some(&self.data[start..end])
    }

    /// Every memo in the file, with the number of the block it is in.
    #[cfg(feature = "foxpro")]
    pub(crate) fn blocks(&self) -> impl Iterator<Item = (u32, &'a [u8])> + '_ {
        let last = (self.data.len() / self.block_size) as u32;
        let last = self.next_free.min(last);
        (self.first_block()..last).filter_map(move |n| self.block(n).map(|b| (n, b)))
    }

    /// The line the report opens with: the file, the size of its blocks,
    /// and how many of them it has.
    pub(crate) fn headline(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "memo file {}: {}-byte blocks, {} blocks allocated",
            self.name, self.block_size, self.next_free
        );
        s
    }
}

/// The text of a memo block.
///
/// A table's memo is text, and it is printed as text. A container's memo
/// is not: it holds the property structure Visual FoxPro wrote, and the
/// names in it are what a search is looking for, so a block that is not
/// text is printed as the printable runs it holds.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
fn memo_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text
        .chars()
        .all(|c| !c.is_control() || c == '\t' || c == '\n' || c == '\r')
    {
        // The line breaks are flattened: a row of a table has to stay a
        // row, and a memo that holds one is still one line of text.
        return text.replace(['\t', '\n', '\r'], " ").trim().to_string();
    }
    printable_runs(bytes)
}

/// The printable runs of a byte string, four bytes or longer, separated by
/// a space.
#[cfg(any(feature = "dbf", feature = "foxpro"))]
fn printable_runs(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut run: Vec<u8> = Vec::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            run.push(b);
        } else {
            push_run(&mut out, &run);
            run.clear();
        }
    }
    push_run(&mut out, &run);
    out
}

#[cfg(any(feature = "dbf", feature = "foxpro"))]
fn push_run(out: &mut String, run: &[u8]) {
    if run.len() < 4 {
        return;
    }
    let text = String::from_utf8_lossy(run);
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(text);
}

/// A memo file as text: every block it holds, with the number of the block
/// it is in.
#[cfg(feature = "foxpro")]
fn memo_dump(file: &MemoFile) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", file.headline());
    for (n, text) in file.blocks() {
        let _ = writeln!(out, "block {n}: {}", memo_text(text));
    }
    out
}

// ---------- Visual FoxPro compound index (.dcx / .cdx) ----------
//
// A compound index holds one B-tree per tag, and it opens with a directory
// of those tags. The directory is a tree of its own: its keys are the names
// of the tags, padded to a fixed length, and the record number of each of
// its entries is the offset of the header of the tag it names.
//
// The header of the file (1024 bytes) holds the root of that directory, the
// length of a tag name and the type code. The header of a tag (1024 bytes
// as well) holds the root of the tag's tree, the length of a key, and two
// expressions: the key expression, and the FOR expression that says which
// rows the tag covers.
//
// Every node of a tree sits in a 512-byte block and starts with the same
// twelve bytes: the attribute (a sum of bits -- 1 is the root, 2 is a
// leaf), the number of keys, and the offsets of the left and right
// siblings. A leaf adds twelve more: the space left between the entry
// table and the key heap, the mask of the record number, and the widths of
// the three fields an entry packs.
//
// A leaf's entries are packed bit by bit from the start of the block: the
// record number, then the number of bytes the key shares with the key
// before it, then the number of pad bytes at the end of the key. The keys
// themselves sit at the end of the block and grow down, each one holding
// only the bytes that differ from the key before it.
//
// The widths of the three packed fields are what the format's own
// documentation gives. They are checked against the bytes here, in the leaf
// header's own identity: the width of the record number, of the duplicate
// count and of the trailing count, added up, is the length of one entry --
// and the space the leaf header says is free is the space the entries and
// the keys do not take.

/// The size of the block every node of a compound index sits in.
#[cfg(feature = "foxpro")]
const CDX_BLOCK: usize = 512;

/// The header of the file, and the header of a tag: two blocks each.
#[cfg(feature = "foxpro")]
const CDX_HEADER: usize = 1024;

/// The node value that means "there is no node here".
#[cfg(feature = "foxpro")]
const CDX_NO_NODE: u32 = 0xffff_ffff;

/// The bit of the type code that marks a compound index.
#[cfg(feature = "foxpro")]
const CDX_COMPOUND: u8 = 0x40;

/// The bit of the node attribute that marks a leaf.
#[cfg(feature = "foxpro")]
const CDX_LEAF: u16 = 0x02;

/// The bytes a node header and a leaf header take: the entry table of a
/// leaf starts right after them.
#[cfg(feature = "foxpro")]
const CDX_LEAF_HEADER: usize = 24;

/// Two bytes, little end first.
#[cfg(feature = "foxpro")]
fn cdx_u16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// Four bytes, little end first.
#[cfg(feature = "foxpro")]
fn cdx_u32(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One node of a tree: the twelve bytes every node of a compound index
/// starts with, and the twelve more a leaf adds.
#[cfg(feature = "foxpro")]
struct CdxNode {
    /// Where the node is in the file.
    offset: usize,
    /// The attribute: a sum of bits. 1 is the root, 2 is a leaf, 4 is a
    /// flag the format's own documentation does not explain.
    attribute: u16,
    /// The number of keys the node holds.
    keys: u16,
    /// The leaf header, for a leaf.
    leaf: Option<CdxLeaf>,
}

/// The twelve bytes a leaf adds to the node header.
#[cfg(feature = "foxpro")]
struct CdxLeaf {
    /// The bytes left between the entry table and the key heap: the heap
    /// starts there.
    free_space: u16,
    /// The mask of the record number.
    record_mask: u32,
    /// The widths, in bits, of the three fields an entry packs.
    record_bits: u32,
    dup_bits: u32,
    trail_bits: u32,
    /// The bytes one packed entry takes.
    info_len: usize,
}

#[cfg(feature = "foxpro")]
impl CdxNode {
    /// The node at `offset`, if the file holds one.
    fn read(data: &[u8], offset: usize) -> Option<Self> {
        // The node has to be inside the file: a node sits in a block, and
        // the block it sits in has to be there whole.
        if offset.checked_add(CDX_BLOCK)? > data.len() {
            return None;
        }
        let attribute = cdx_u16(data, offset)?;
        let keys = cdx_u16(data, offset + 2)?;
        let leaf = if attribute & CDX_LEAF != 0 {
            Some(CdxLeaf {
                free_space: cdx_u16(data, offset + 0x0c)?,
                record_mask: cdx_u32(data, offset + 0x0e)?,
                record_bits: *data.get(offset + 0x14)? as u32,
                dup_bits: *data.get(offset + 0x15)? as u32,
                trail_bits: *data.get(offset + 0x16)? as u32,
                info_len: *data.get(offset + 0x17)? as usize,
            })
        } else {
            None
        };
        Some(CdxNode {
            offset,
            attribute,
            keys,
            leaf,
        })
    }
}

/// One key of a tree: the row it points at, and what the key says.
#[cfg(feature = "foxpro")]
struct CdxKey {
    /// The row the key points at: a row of the table the index is over.
    record: u32,
    /// The bytes of the key, with the pad at its end taken off.
    bytes: Vec<u8>,
}

/// The three fields one packed entry of a leaf carries.
#[cfg(feature = "foxpro")]
struct CdxEntry {
    /// The row the key points at.
    record: u32,
    /// The bytes the key shares with the key before it.
    dup: u32,
    /// The pad bytes at the end of the key.
    trail: u32,
}

/// The entry `index` of a leaf: three fields packed bit by bit into the
/// entry table that grows up from the start of the block.
#[cfg(feature = "foxpro")]
fn cdx_entry(data: &[u8], node: &CdxNode, leaf: &CdxLeaf, index: usize) -> Option<CdxEntry> {
    // The three widths have to fit the entry, the record number is masked
    // with 32 bits, and the entry itself has to fit the 64 bits the packed
    // value is read into.
    if leaf.info_len == 0
        || leaf.info_len > 8
        || leaf.record_bits > 32
        || leaf.dup_bits > 32
        || leaf.trail_bits > 32
        || leaf.record_bits + leaf.dup_bits + leaf.trail_bits > 64
    {
        return None;
    }
    let at = node.offset + CDX_LEAF_HEADER + index * leaf.info_len;
    let mut packed: u64 = 0;
    for byte in 0..leaf.info_len {
        packed |= (*data.get(at + byte)? as u64) << (8 * byte);
    }
    let record = (packed & leaf.record_mask as u64) as u32;
    let dup = (packed >> leaf.record_bits) & ((1u64 << leaf.dup_bits) - 1);
    // The two shifts are one at a time: the sum of the two widths can be a
    // whole word, and a shift by the width of the word is not one.
    let trail = (packed >> leaf.record_bits >> leaf.dup_bits) & ((1u64 << leaf.trail_bits) - 1);
    Some(CdxEntry {
        record,
        dup: dup as u32,
        trail: trail as u32,
    })
}

/// The keys of a leaf, in order, with the row each one points at.
#[cfg(feature = "foxpro")]
fn cdx_leaf_keys(
    data: &[u8],
    node: &CdxNode,
    leaf: &CdxLeaf,
    key_len: usize,
) -> Option<Vec<CdxKey>> {
    let mut out = Vec::with_capacity(node.keys as usize);
    let mut previous: Vec<u8> = Vec::new();
    // The key heap is the space between the entry table and the end of the
    // block, and it grows down: every key holds only the bytes that differ
    // from the key before it.
    let heap_start = node.offset + leaf.free_space.min(CDX_BLOCK as u16) as usize;
    let mut at = node.offset.checked_add(CDX_BLOCK)?;
    for index in 0..node.keys as usize {
        let entry = cdx_entry(data, node, leaf, index)?;
        let dup = entry.dup as usize;
        let trail = entry.trail as usize;
        let len = key_len.checked_sub(dup.checked_add(trail)?)?;
        at = at.checked_sub(len)?;
        if at < heap_start || dup > previous.len() {
            return None;
        }
        let mut bytes = Vec::with_capacity(dup + len);
        bytes.extend_from_slice(&previous[..dup]);
        bytes.extend_from_slice(data.get(at..at + len)?);
        out.push(CdxKey {
            record: entry.record,
            bytes,
        });
        previous = out[index].bytes.clone();
    }
    Some(out)
}

/// Every key of the tree at `root`, in order, with the row each one points
/// at.
#[cfg(feature = "foxpro")]
fn cdx_tree(data: &[u8], root: u32, key_len: usize) -> Option<Vec<CdxKey>> {
    let mut out = Vec::new();
    cdx_walk(data, root, key_len, 0, &mut out)?;
    Some(out)
}

/// The keys of the tree at `node`, in order.
#[cfg(feature = "foxpro")]
fn cdx_walk(
    data: &[u8],
    node: u32,
    key_len: usize,
    depth: usize,
    out: &mut Vec<CdxKey>,
) -> Option<()> {
    // A tree is shallow -- three levels in every file of the corpus -- and a
    // file that points a node at itself would otherwise walk forever.
    if depth > 16 || node == CDX_NO_NODE {
        return None;
    }
    let offset = node as usize;
    let head = CdxNode::read(data, offset)?;
    if head.attribute & CDX_LEAF != 0 {
        let leaf = head.leaf.as_ref()?;
        out.extend(cdx_leaf_keys(data, &head, leaf, key_len)?);
        return Some(());
    }
    // An interior node holds one entry per child, in order: the entry's own
    // key is the last key of the child it points at, and the child holds the
    // keys that come before it. The siblings of the node are not needed for
    // that -- the children of the node are the leaves themselves.
    let step = key_len.checked_add(8)?;
    for index in 0..head.keys as usize {
        let at = offset
            .checked_add(12)?
            .checked_add(index.checked_mul(step)?)?;
        let child = u32::from_be_bytes([
            *data.get(at + key_len + 4)?,
            *data.get(at + key_len + 5)?,
            *data.get(at + key_len + 6)?,
            *data.get(at + key_len + 7)?,
        ]);
        cdx_walk(data, child, key_len, depth + 1, out)?;
    }
    Some(())
}

/// One tag of a compound index: what its header says and where its tree is.
#[cfg(feature = "foxpro")]
struct CdxTag {
    /// The name the directory gives the tag.
    name: String,
    /// Where the root of the tag's tree is.
    root: u32,
    /// The length of a key, in bytes.
    key_len: usize,
    /// The expression that says what a key is.
    expression: String,
    /// The FOR expression that says which rows the tag covers.
    filter: String,
}

/// The tag whose header is at `header`, if the file holds one.
#[cfg(feature = "foxpro")]
fn cdx_tag(data: &[u8], header: usize, name: String) -> Option<CdxTag> {
    // The header of a tag is two blocks, and it has to be inside the file.
    if header.checked_add(CDX_HEADER)? > data.len() {
        return None;
    }
    let root = cdx_u32(data, header)?;
    let key_len = cdx_u16(data, header + 0x0c)? as usize;
    // The expression area of a header is 512 bytes: the key expression
    // first, then the FOR expression, each one ended by a NUL.
    let expression_len = cdx_u16(data, header + 0x1fe)? as usize;
    let filter_len = cdx_u16(data, header + 0x1fa)? as usize;
    let expression_at = cdx_u16(data, header + 0x1fc)? as usize;
    let filter_at = cdx_u16(data, header + 0x1f8)? as usize;
    let area =
        data.get(header.checked_add(0x200)?..header.checked_add(0x200)?.checked_add(CDX_BLOCK)?)?;
    let expression = cdx_text(area.get(expression_at..expression_at + expression_len)?);
    let filter = cdx_text(area.get(filter_at..filter_at + filter_len)?);
    Some(CdxTag {
        name,
        root,
        key_len,
        expression,
        filter,
    })
}

/// The text of an expression: the bytes up to the NUL that ends it.
#[cfg(feature = "foxpro")]
fn cdx_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// A Visual FoxPro compound index: the `.dcx` beside a database container,
/// or the `.cdx` beside a table.
#[cfg(feature = "foxpro")]
struct CompoundIndex<'a> {
    data: &'a [u8],
    /// Where the root of the tag directory is.
    root: u32,
    /// The length of a tag name, in bytes.
    name_len: usize,
}

#[cfg(feature = "foxpro")]
impl<'a> CompoundIndex<'a> {
    /// The compound index in `data`, if it is one.
    fn open(data: &'a [u8]) -> Option<Self> {
        if data.len() < CDX_HEADER {
            return None;
        }
        // The type code says what the file is: the compound bit marks a file
        // whose first header is the directory of its tags.
        if *data.get(0x0e)? & CDX_COMPOUND == 0 {
            return None;
        }
        let root = cdx_u32(data, 0)?;
        if root == CDX_NO_NODE || root < CDX_HEADER as u32 {
            return None;
        }
        let name_len = cdx_u16(data, 0x0c)? as usize;
        if name_len == 0 || name_len > 64 {
            return None;
        }
        Some(CompoundIndex {
            data,
            root,
            name_len,
        })
    }

    /// The tags the file holds, in the order the directory spells them.
    fn tags(&self) -> Option<Vec<CdxTag>> {
        let entries = cdx_tree(self.data, self.root, self.name_len)?;
        let mut tags = Vec::with_capacity(entries.len());
        for entry in entries {
            let name = String::from_utf8_lossy(&entry.bytes)
                .trim_end_matches(' ')
                .to_string();
            tags.push(cdx_tag(self.data, entry.record as usize, name)?);
        }
        Some(tags)
    }
}

/// A key as text: the bytes of it when they are text, and their hex when
/// they are not.
#[cfg(feature = "foxpro")]
fn cdx_key_text(key: &[u8]) -> String {
    let mut out = String::new();
    if key.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        let _ = write!(out, "\"{}\"", String::from_utf8_lossy(key));
    } else {
        out.push_str("0x");
        for byte in key {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out
}

/// A compound index as text: every tag, the expression that says what its
/// keys are, and the row each key points at.
#[cfg(feature = "foxpro")]
fn cdx_dump(data: &[u8], path: &str) -> Result<String> {
    let Some(index) = CompoundIndex::open(data) else {
        decline!("not a Visual FoxPro compound index");
    };
    let Some(tags) = index.tags() else {
        bail!("the compound index's tag directory could not be read");
    };
    let mut out = String::new();
    let _ = writeln!(out, "compound index {path}: {} tags", tags.len());
    for (n, tag) in tags.iter().enumerate() {
        let _ = writeln!(out, "tag {}: {}", n + 1, tag.name);
        let _ = writeln!(out, "  key expression: {}", tag.expression);
        if !tag.filter.is_empty() {
            let _ = writeln!(out, "  for expression: {}", tag.filter);
        }
        let _ = writeln!(out, "  key length: {} bytes", tag.key_len);
        let Some(keys) = cdx_tree(data, tag.root, tag.key_len) else {
            bail!("the tree of the tag {} could not be read", tag.name);
        };
        let _ = writeln!(out, "  rows: {}", keys.len());
        for key in &keys {
            let _ = writeln!(out, "  row {}: {}", key.record, cdx_key_text(&key.bytes));
        }
    }
    Ok(out)
}

/// The facts a compound index offers: the name of every tag it holds.
#[cfg(feature = "foxpro")]
fn cdx_facts(data: &[u8]) -> Vec<Field> {
    let mut facts = Vec::new();
    if let Some(index) = CompoundIndex::open(data) {
        if let Some(tags) = index.tags() {
            for tag in tags {
                facts.push(Field::new("index.tag", &tag.name));
            }
        }
    }
    facts
}

/// Visual FoxPro: the database container (`.dbc`), the memo file that
/// holds the text its rows point at, and the compound index that says
/// which rows there are.
///
/// The container is a dBase table with a different extension, so the dBase
/// reader reads it; what this adds is the memo file beside it, which is
/// where the text of a memo field lives. The container's rows name the
/// block their text is in, and the memo file has that block, so the two are
/// read together and the row carries the text rather than the number.
///
/// The compound index (`.dcx` beside a container, `.cdx` beside a table) is
/// the index over those rows: it names its tags, says the expression each
/// tag's keys are built from, and says which row every key points at.
#[cfg(feature = "foxpro")]
pub(crate) struct Foxpro;

#[cfg(feature = "foxpro")]
impl Adapter for Foxpro {
    fn name(&self) -> &'static str {
        "foxpro"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dbc", "dct", "fpt", "dcx", "cdx"]
    }

    fn extract(&self, data: &[u8], path: &str) -> Result<Outcome> {
        match extension(path).as_str() {
            "dct" | "fpt" => {
                let Some(file) = MemoFile::open(path, data) else {
                    decline!("not a Visual FoxPro memo file");
                };
                Ok(Outcome::Text(memo_dump(&file).into_bytes()))
            }
            "dbc" => {
                // The memo file of a container is beside it, with the same
                // name and the `.dct` extension.
                let Some((name, bytes)) = companion(path) else {
                    decline!("no memo file beside the container");
                };
                let Some(file) = MemoFile::open(&name, &bytes) else {
                    decline!("the file beside the container is not a memo file");
                };
                Ok(Outcome::Text(dbf_dump(data, Some(&file))?.into_bytes()))
            }
            "dcx" | "cdx" => Ok(Outcome::Text(cdx_dump(data, path)?.into_bytes())),
            _ => decline!("not a Visual FoxPro file"),
        }
    }

    /// The facts the `--filter` asks about: the name of every column, or
    /// the name of every tag when the file is an index.
    fn facts(&self, data: &[u8], path: &str) -> Vec<Field> {
        match extension(path).as_str() {
            "dcx" | "cdx" => cdx_facts(data),
            _ => dbf_facts(data),
        }
    }
}

/// The lowercased extension of a path.
#[cfg(feature = "foxpro")]
fn extension(path: &str) -> String {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((_, ext)) => ext.to_ascii_lowercase(),
        None => String::new(),
    }
}

/// The memo file beside a container: the same name with the `.dct`
/// extension, in the same directory.
///
/// Visual FoxPro writes the extension in upper case and a file that came
/// from somewhere else may have it in lower case, so both are tried.
#[cfg(feature = "std")]
#[cfg(feature = "foxpro")]
fn companion(path: &str) -> Option<(String, Vec<u8>)> {
    let base = std::path::Path::new(path);
    for ext in ["DCT", "dct"] {
        let candidate = base.with_extension(ext);
        if let Ok(bytes) = std::fs::read(&candidate) {
            return Some((candidate.to_string_lossy().into_owned(), bytes));
        }
    }
    None
}

/// The memo file beside a container, without a filesystem to look in: there
/// is none, and the container's rows keep the block numbers.
#[cfg(not(feature = "std"))]
#[cfg(feature = "foxpro")]
fn companion(_path: &str) -> Option<(String, Vec<u8>)> {
    None
}

#[cfg(test)]
#[cfg(any(feature = "bson", feature = "foxpro", feature = "redis-rdb"))]
mod tests {
    use super::*;
    use alloc::string::String;
    #[cfg(any(feature = "foxpro", feature = "redis-rdb"))]
    use alloc::vec;
    use alloc::vec::Vec;

    #[cfg(any(feature = "bson", feature = "redis-rdb"))]
    fn text(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    /// BSON writer for the shapes the reader claims, built by hand so the
    /// fixture is the spec rather than the writer.
    #[cfg(feature = "bson")]
    struct Doc(Vec<u8>);
    #[cfg(feature = "bson")]
    impl Doc {
        fn new() -> Self {
            Doc(Vec::new())
        }
        fn str(mut self, k: &str, v: &str) -> Self {
            self.0.push(BSON_STRING);
            self.0.extend_from_slice(k.as_bytes());
            self.0.push(0);
            self.0
                .extend_from_slice(&((v.len() + 1) as u32).to_le_bytes());
            self.0.extend_from_slice(v.as_bytes());
            self.0.push(0);
            self
        }
        fn i32(mut self, k: &str, v: i32) -> Self {
            self.0.push(BSON_INT32);
            self.0.extend_from_slice(k.as_bytes());
            self.0.push(0);
            self.0.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn sub(mut self, k: &str, d: Doc) -> Self {
            let body = d.finish();
            self.0.push(BSON_DOC);
            self.0.extend_from_slice(k.as_bytes());
            self.0.push(0);
            self.0.extend_from_slice(&body);
            self
        }
        fn objectid(mut self, k: &str, bytes: [u8; 12]) -> Self {
            self.0.push(BSON_OBJECTID);
            self.0.extend_from_slice(k.as_bytes());
            self.0.push(0);
            self.0.extend_from_slice(&bytes);
            self
        }
        fn finish(self) -> Vec<u8> {
            let mut out = ((self.0.len() + 5) as u32).to_le_bytes().to_vec();
            out.extend_from_slice(&self.0);
            out.push(0);
            out
        }
    }

    #[test]
    #[cfg(feature = "bson")]
    fn bson_fields_and_nested_documents_are_read() {
        let d = Doc::new()
            .str("name", "invoice")
            .i32("total", 42)
            .sub(
                "customer",
                Doc::new().str("city", "Curitiba").i32("since", 2019),
            )
            .objectid("id", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
            .finish();
        let out = text(Bson.extract(&d, "x.bson").expect("bson"));
        assert!(out.contains("name: string invoice"), "{out}");
        assert!(out.contains("total: int32 42"), "{out}");
        assert!(out.contains("customer.city: string Curitiba"), "{out}");
        assert!(out.contains("customer.since: int32 2019"), "{out}");
        assert!(
            out.contains("id: objectid 0102030405060708090a0b0c"),
            "{out}"
        );
        assert!(out.contains("documents: 1"), "{out}");
    }

    #[test]
    #[cfg(feature = "bson")]
    fn bson_reads_a_stream_of_documents() {
        let a = Doc::new().str("k", "one").finish();
        let b = Doc::new().str("k", "two").finish();
        let mut d = a;
        d.extend_from_slice(&b);
        let out = text(Bson.extract(&d, "stream.bson").expect("bson"));
        assert!(out.contains("k: string one"), "{out}");
        assert!(out.contains("k: string two"), "{out}");
        assert!(out.contains("documents: 2"), "{out}");
    }

    #[test]
    #[cfg(feature = "bson")]
    fn bson_declines_a_length_that_runs_past_the_file() {
        let mut d = Doc::new().str("a", "b").finish();
        d[0..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(Bson.extract(&d, "x.bson").is_err());
        assert!(Bson.extract(b"not bson at all", "x.bson").is_err());
    }

    // ---- Redis fixtures ----

    /// `rdbSaveLen`, so the fixture writes lengths the way Redis writes them.
    #[cfg(feature = "redis-rdb")]
    fn len(v: u64, out: &mut Vec<u8>) {
        if v < (1 << 6) {
            out.push(v as u8);
        } else if v < (1 << 14) {
            out.push(((v >> 8) as u8) | 0x40);
            out.push(v as u8);
        } else {
            out.push(RDB_32BITLEN);
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
    }

    #[cfg(feature = "redis-rdb")]
    fn str_bytes(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        len(s.len() as u64, &mut out);
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// A listpack blob is not UTF-8, so the fixture needs raw bytes.
    #[cfg(feature = "redis-rdb")]
    fn raw_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        len(b.len() as u64, &mut out);
        out.extend_from_slice(b);
        out
    }

    /// An LZF stream built by hand: a back reference is the only thing a
    /// fixture needs to prove the decoder runs, and emitting all literals
    /// would prove nothing.
    #[cfg(feature = "redis-rdb")]
    fn lzf_compress(src: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        // Literal runs of at most 32 bytes.
        for chunk in src.chunks(32) {
            out.push((chunk.len() - 1) as u8);
            out.extend_from_slice(chunk);
        }
        out
    }

    #[cfg(feature = "redis-rdb")]
    fn rdb_blob(compressed: &[u8], ulen: usize) -> Vec<u8> {
        let mut out = vec![(0xC0u8 | RDB_ENC_LZF)];
        len(compressed.len() as u64, &mut out);
        len(ulen as u64, &mut out);
        out.extend_from_slice(compressed);
        out
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_keys_types_and_values_are_read() {
        let mut d = b"REDIS0009".to_vec();
        d.push(OP_AUX);
        d.extend_from_slice(&str_bytes("redis-ver"));
        d.extend_from_slice(&str_bytes("7.2.4"));
        d.push(OP_SELECTDB);
        d.push(0x00);
        d.push(RDB_STRING);
        d.extend_from_slice(&str_bytes("session:42"));
        d.extend_from_slice(&str_bytes("abc123"));
        d.push(RDB_HASH);
        d.extend_from_slice(&str_bytes("user:1"));
        d.push(2);
        d.extend_from_slice(&str_bytes("name"));
        d.extend_from_slice(&str_bytes("dana"));
        d.extend_from_slice(&str_bytes("city"));
        d.extend_from_slice(&str_bytes("curitiba"));
        d.push(OP_EOF);
        d.extend_from_slice(&[0u8; 8]);

        let out = text(RedisRdb.extract(&d, "dump.rdb").expect("rdb"));
        assert!(out.contains("rdb version 9"), "{out}");
        assert!(out.contains("aux redis-ver: 7.2.4"), "{out}");
        assert!(out.contains("select db 0"), "{out}");
        assert!(out.contains("session:42: string abc123"), "{out}");
        assert!(out.contains("user:1: hash (2 entries)"), "{out}");
        assert!(out.contains("name: dana"), "{out}");
        assert!(out.contains("eof after 2 keys"), "{out}");
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_an_integer_encoded_string_is_a_number_not_a_length() {
        // `0xC0|INT8` is one signed byte. Read as a length it would be zero,
        // the value after it would be read as the next key, and the keyspace
        // would come out as nonsense three records in. Redis integer-encodes
        // any string of at most eleven bytes that parses as a number, which
        // is exactly why numeric keys are common in a real dump.
        let mut d = b"REDIS0009".to_vec();
        for (enc, raw, name) in [
            // 100 and not 200: `rdbEncodeInteger` picks INT8 only for
            // -128..=127, and 200 would be read as -56 — correctly, because
            // that is what the one byte says.
            (0xC0u8, 100i8.to_le_bytes().to_vec(), "100"),
            (0xC1, 1000i16.to_le_bytes().to_vec(), "1000"),
            (0xC2, (-70000i32).to_le_bytes().to_vec(), "-70000"),
        ] {
            d.push(RDB_STRING);
            d.push(enc);
            d.extend_from_slice(&raw);
            d.extend_from_slice(&str_bytes(&format!("value-of-{name}")));
        }
        d.push(OP_EOF);
        d.extend_from_slice(&[0u8; 8]);

        let out = text(RedisRdb.extract(&d, "dump.rdb").expect("rdb"));
        assert!(out.contains("key[0] 100: string value-of-100"), "{out}");
        assert!(out.contains("key[0] 1000: string value-of-1000"), "{out}");
        assert!(
            out.contains("key[0] -70000: string value-of--70000"),
            "{out}"
        );
        assert!(out.contains("eof after 3 keys"), "{out}");
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_an_lzf_string_decompresses_to_its_value() {
        let plain = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbb".to_vec();
        let packed = lzf_compress(&plain);
        let mut d = b"REDIS0011".to_vec();
        d.push(RDB_STRING);
        d.extend_from_slice(&str_bytes("blob"));
        d.extend_from_slice(&rdb_blob(&packed, plain.len()));
        d.push(OP_EOF);
        d.extend_from_slice(&[0u8; 8]);

        let out = text(RedisRdb.extract(&d, "dump.rdb").expect("rdb"));
        assert!(out.contains("bbbb"), "{out}");
        assert!(!out.contains("did not decompress"), "{out}");
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn lzf_back_references_copy_from_the_window_already_written() {
        // A literal run of four, then three back references of length 8 at
        // offset 4. `ctrl >> 5` is the length before the +2, so 8 means 6;
        // and the low byte is offset - 1, which is what the "+1" in the
        // decoder is for.
        let mut s = vec![3u8];
        s.extend_from_slice(b"abcd");
        for _ in 0..3 {
            s.push(6 << 5);
            s.push(3);
        }
        let mut out = vec![0u8; 32];
        let n = lzf_decompress(&s, &mut out).expect("decompresses");
        assert_eq!(&out[..n], b"abcdabcdabcdabcdabcdabcdabcd");
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_a_packed_list_is_one_blob_not_a_count() {
        // The listpack's own entry count is not an RDB length. Reading it as
        // one is the mistake that turns a set into a stream of garbage.
        let mut d = b"REDIS0011".to_vec();
        d.push(RDB_SET_LISTPACK);
        d.extend_from_slice(&str_bytes("tags"));
        d.extend_from_slice(&raw_bytes(b"a\xc5red\xc4blue\xc4zset"));
        d.push(RDB_STRING);
        d.extend_from_slice(&str_bytes("after"));
        d.extend_from_slice(&str_bytes("still-here"));
        d.push(OP_EOF);
        d.extend_from_slice(&[0u8; 8]);

        let out = text(RedisRdb.extract(&d, "dump.rdb").expect("rdb"));
        assert!(out.contains("tags: set ("), "{out}");
        assert!(out.contains("after: string still-here"), "{out}");
        assert!(out.contains("eof after 2 keys"), "{out}");
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_length_rejects_a_32_bit_prefix_that_is_not_one() {
        // 0x80 is the 32-bit length; 0x82 shares its top bits and is corrupt.
        let d = [0x80u8, 0, 0, 1, 0];
        assert!(matches!(rdb_len(&d, 0), Some(RdbLen::Len(256, 5))));
        let d = [0x82u8, 0, 0, 1, 0];
        assert!(rdb_len(&d, 0).is_none(), "0x82 is not a length prefix");
        // 0xC3 is LZF, not the length 3.
        let d = [0xC3u8];
        assert_eq!(rdb_len(&d, 0), Some(RdbLen::Encoded(RDB_ENC_LZF, 1)));
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_length_decodes_every_width() {
        // The 6-bit form tops out at 63; 0x7F is the 14-bit form with a zero
        // low byte, which is the mistake a hand-written encoder makes.
        assert_eq!(rdb_len(&[0x3Fu8, 0x00], 0), Some(RdbLen::Len(63, 1)));
        assert_eq!(rdb_len(&[0x41u8, 0x00, 0x00], 0), Some(RdbLen::Len(256, 2)));
        assert_eq!(rdb_len(&[0x80u8, 0, 0, 1, 0], 0), Some(RdbLen::Len(256, 5)));
        // The 64-bit form is the one a `first >> 6 == 2` branch eats: 2^32 is
        // representable in the 32-bit form and in the 64-bit one, so only a
        // value above it can tell the two apart. The fixture is built with
        // the same `to_be_bytes` the writer uses.
        let mut d = vec![RDB_64BITLEN];
        d.extend_from_slice(&(1u64 << 32).to_be_bytes());
        assert_eq!(rdb_len(&d, 0), Some(RdbLen::Len(1 << 32, 9)));
    }

    #[test]
    #[cfg(feature = "redis-rdb")]
    fn rdb_declines_a_file_that_is_not_one() {
        assert!(RedisRdb.extract(b"SQLite format 3\0", "x.rdb").is_err());
        assert!(RedisRdb.extract(b"REDIS9999", "x.rdb").is_err());
    }

    // -- Visual FoxPro: the container, its memo file, and the block the
    // -- two agree on --

    /// The path of a fixture in `testdata/foxpro`.
    #[cfg(feature = "foxpro")]
    fn foxpro_path(name: &str) -> String {
        format!(
            "{}{}",
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/foxpro/"),
            name
        )
    }

    /// The bytes of a fixture in `testdata/foxpro`.
    #[cfg(feature = "foxpro")]
    fn foxpro_fixture(name: &str) -> Vec<u8> {
        std::fs::read(foxpro_path(name)).expect("the fixture")
    }

    /// The value of the column `name` in the row `row` of a dBase table.
    #[cfg(feature = "foxpro")]
    fn dbf_cell(dbf: &[u8], row: usize, name: &str) -> Vec<u8> {
        let header_size = u16::from_le_bytes([dbf[8], dbf[9]]) as usize;
        let record_size = u16::from_le_bytes([dbf[10], dbf[11]]) as usize;
        let fields = dbf_fields(dbf, header_size);
        let f = fields.iter().find(|f| f.name == name).expect("the column");
        let start = header_size + row * record_size + f.offset;
        dbf[start..start + f.len].to_vec()
    }

    /// The rows of a container: the type of the object, its name, and the
    /// block its property lives in.
    #[cfg(feature = "foxpro")]
    fn container_rows(dbc: &[u8]) -> Vec<(String, String, u32)> {
        let n = u32::from_le_bytes([dbc[4], dbc[5], dbc[6], dbc[7]]) as usize;
        let mut rows = Vec::new();
        for row in 0..n {
            let kind = dbf_cell(dbc, row, "OBJECTTYPE");
            let name = dbf_cell(dbc, row, "OBJECTNAME");
            let prop = dbf_cell(dbc, row, "PROPERTY");
            rows.push((
                String::from_utf8_lossy(&kind).trim().to_string(),
                String::from_utf8_lossy(&name).trim().to_string(),
                u32::from_le_bytes([prop[0], prop[1], prop[2], prop[3]]),
            ));
        }
        rows
    }

    /// The letters of a name, in lower case: what two spellings of the
    /// same name have in common.
    #[cfg(feature = "foxpro")]
    fn letters(name: &str) -> String {
        name.chars()
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }

    /// Whether the letters of `short` are the letters of `long`, in order.
    ///
    /// A container calls a field by an identifier and the memo holds the
    /// name the field carries, and the two can be spelled differently --
    /// "State/Province" against "stateorprovince" -- so the relation
    /// checked here is the weaker one that still fails for a block that
    /// holds somebody else's name.
    #[cfg(feature = "foxpro")]
    fn letters_in_order(short: &str, long: &str) -> bool {
        let mut rest = long.chars();
        short.chars().all(|c| rest.any(|r| r == c))
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn a_memo_field_points_at_the_block_that_holds_its_text() {
        // The row names the block and the block holds the text: the first
        // employee's address, and the town the same row gives. The memo
        // file's own header says how many blocks it has, and that is one
        // past the last block the table points at.
        let dbf = foxpro_fixture("employees.dbf");
        let fpt = foxpro_fixture("employees.FPT");
        let memo = MemoFile::open("employees.FPT", &fpt).expect("a memo file");
        assert_eq!(memo.block_size, 64);
        // The header record is 512 bytes, so the first memo is the eighth
        // block of a file whose blocks are 64 bytes.
        assert_eq!(memo.first_block(), 8);

        let n = u32::from_le_bytes([dbf[4], dbf[5], dbf[6], dbf[7]]) as usize;
        let mut last = 0;
        for row in 0..n {
            let cell = dbf_cell(&dbf, row, "ADDRESS");
            let block = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]);
            assert!(block >= memo.first_block(), "row {row} names block {block}");
            let text = memo_text(memo.block(block).expect("the block the row names"));
            assert!(!text.is_empty(), "row {row} names an empty block");
            last = last.max(block);
        }
        assert_eq!(
            last + 1,
            memo.next_free,
            "the file's own count of its blocks"
        );

        let cell = dbf_cell(&dbf, 0, "ADDRESS");
        let block = u32::from_le_bytes([cell[0], cell[1], cell[2], cell[3]]);
        assert_eq!(memo_text(memo.block(block).unwrap()), "908 W. Capital Way");
        assert_eq!(
            String::from_utf8_lossy(&dbf_cell(&dbf, 0, "CITY")).trim(),
            "Tacoma"
        );
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_field_a_container_names_is_the_field_its_memo_holds() {
        // The container's rows name the fields of the tables it binds, and
        // the memo block each of those rows points at holds the name of
        // the field -- the same name, in the spelling the field carries.
        let dbc = foxpro_fixture("EXPENSES.DBC");
        let dct = foxpro_fixture("EXPENSES.DCT");
        let memo = MemoFile::open("EXPENSES.DCT", &dct).expect("a memo file");
        let mut checked = 0;
        for (kind, name, block) in container_rows(&dbc) {
            if kind != "Field" {
                continue;
            }
            let text = memo_text(memo.block(block).expect("the block the row names"));
            assert!(
                letters_in_order(&letters(&text), &letters(&name)),
                "the memo block {block} of {name} holds {text}"
            );
            checked += 1;
        }
        assert!(checked >= 16, "the container names {checked} fields");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_table_a_container_binds_is_the_file_its_memo_names() {
        // The container's row for a table points at a memo block, and that
        // block names the table's own file. The container, the memo file
        // and the file on disk are three artifacts that agree.
        let dbc = foxpro_fixture("EXPENSES.DBC");
        let dct = foxpro_fixture("EXPENSES.DCT");
        let memo = MemoFile::open("EXPENSES.DCT", &dct).expect("a memo file");
        let mut checked = 0;
        for (kind, name, block) in container_rows(&dbc) {
            if kind != "Table" {
                continue;
            }
            let text = memo_text(memo.block(block).expect("the block the row names"));
            // The container spells a name that has a space in it with an
            // underscore, and the file the name is of spells it with the
            // space: "expense_categories" is "expense categories.dbf".
            assert!(
                text.contains(&format!("{}.dbf", name.replace('_', " "))),
                "the memo block {block} of {name} holds {text}"
            );
            checked += 1;
        }
        assert_eq!(checked, 4, "the container binds four tables");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_container_reports_the_text_of_its_memo_fields() {
        // The container's rows name the block their text is in; with the
        // memo file beside it, the row carries the text.
        let path = foxpro_path("EXPENSES.DBC");
        let data = foxpro_fixture("EXPENSES.DBC");
        let out = match Foxpro
            .extract(&data, &path)
            .expect("a container with its memo file beside it")
        {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("text"),
        };
        assert!(out.contains("memo file"), "{out}");
        assert!(
            out.contains("Employee ID"),
            "the text of a memo field: {out}"
        );
        assert!(out.contains("expense details.dbf"), "{out}");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn a_memo_file_is_read_as_the_blocks_it_holds() {
        let path = foxpro_path("employees.FPT");
        let data = foxpro_fixture("employees.FPT");
        let out = match Foxpro.extract(&data, &path).expect("a memo file") {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("text"),
        };
        assert!(out.contains("64-byte blocks"), "{out}");
        assert!(out.contains("908 W. Capital Way"), "{out}");
        assert!(out.contains("722 Moss Bay Blvd."), "{out}");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn a_file_that_is_not_a_memo_file_is_declined() {
        assert!(Foxpro.extract(&vec![0u8; 1024], "x.dct").is_err());
        assert!(Foxpro.extract(&vec![0u8; 1024], "x.fpt").is_err());
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_compound_index_names_its_tags_and_the_rows_they_point_at() {
        // The index of a container is a compound index: it opens with a
        // directory of its tags, and each tag says what its keys are built
        // from and which row every key points at.
        let path = foxpro_path("EXPENSES.DCX");
        let data = foxpro_fixture("EXPENSES.DCX");
        let out = match Foxpro.extract(&data, &path).expect("a compound index") {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("text"),
        };
        // The two tags the directory names, and what their headers say.
        assert!(out.contains("tag 1: OBJECTNAME"), "{out}");
        assert!(out.contains("tag 2: OBJECTTYPE"), "{out}");
        assert!(
            out.contains("key expression: STR(parentid)+objecttype+LOWER(objectname)\n"),
            "{out}"
        );
        assert!(
            out.contains("key expression: STR(parentid)+objecttype\n"),
            "{out}"
        );
        assert!(out.contains("for expression: .NOT.DELETED()"), "{out}");
        assert!(out.contains("key length: 148 bytes"), "{out}");
        assert!(out.contains("key length: 20 bytes"), "{out}");
        // The rows. The key is what the row says, with the pad at its end
        // taken off: the first tag's key holds the name of the object, the
        // second tag's key holds only its type.
        assert!(
            out.contains("row 1: \"         1Database  database\""),
            "{out}"
        );
        assert!(out.contains("row 1: \"         1Database\""), "{out}");
        assert!(
            out.contains("row 57: \"        34Relation  relation 1\""),
            "{out}"
        );
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_rows_the_index_points_at_are_the_rows_the_container_keeps() {
        // The container is the oracle. Its rows are the ones the index
        // points at -- the FOR expression keeps the deleted ones out -- and
        // every key of the index is what the row it points at says.
        let dbc = foxpro_fixture("EXPENSES.DBC");
        let data = foxpro_fixture("EXPENSES.DCX");
        let header_size = u16::from_le_bytes([dbc[8], dbc[9]]) as usize;
        let record_size = u16::from_le_bytes([dbc[10], dbc[11]]) as usize;
        let rows = u32::from_le_bytes([dbc[4], dbc[5], dbc[6], dbc[7]]) as usize;

        // The rows the container keeps: the ones that are not deleted.
        let mut kept: Vec<u32> = Vec::new();
        for row in 0..rows {
            if dbc[header_size + row * record_size] != b'*' {
                kept.push(row as u32 + 1);
            }
        }
        assert_eq!(kept.len(), 57, "57 of the container's 59 rows are kept");

        let index = CompoundIndex::open(&data).expect("a compound index");
        let tags = index.tags().expect("its tags");
        assert_eq!(tags.len(), 2);
        for tag in &tags {
            let keys = cdx_tree(&data, tag.root, tag.key_len).expect("the tree of the tag");
            // The rows the tag points at are the rows the container keeps.
            let mut pointed: Vec<u32> = keys.iter().map(|k| k.record).collect();
            pointed.sort_unstable();
            pointed.dedup();
            assert_eq!(pointed, kept, "the rows of the tag {}", tag.name);
            // And every key is what the row it points at says: the parent
            // id right-aligned in ten characters, the type of the object,
            // and -- for the tag whose expression asks for it -- the name
            // of the object in lower case.
            for key in &keys {
                let row = key.record as usize - 1;
                let parent = dbf_cell(&dbc, row, "PARENTID");
                let parent = u32::from_le_bytes([parent[0], parent[1], parent[2], parent[3]]);
                let kind = String::from_utf8_lossy(&dbf_cell(&dbc, row, "OBJECTTYPE")).into_owned();
                let name = String::from_utf8_lossy(&dbf_cell(&dbc, row, "OBJECTNAME")).into_owned();
                let want = match tag.name.as_str() {
                    "OBJECTNAME" => format!("{parent:>10}{kind}{}", name.to_lowercase()),
                    "OBJECTTYPE" => format!("{parent:>10}{kind}"),
                    other => panic!("an unexpected tag: {other}"),
                };
                let got = String::from_utf8_lossy(&key.bytes).into_owned();
                assert_eq!(got, want.trim_end(), "the key of row {}", key.record);
            }
        }
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_header_of_the_compound_index_says_what_the_format_says() {
        // The values the format's own documentation gives, read straight from
        // the file's bytes: the type codes, the length of a key, the chain
        // of leaves, and the widths of the three fields every entry of a
        // leaf packs.
        let data = foxpro_fixture("EXPENSES.DCX");
        // The header of the file: the root of the tag directory, the length
        // of a tag name, and the type code that says the file is a compound
        // index.
        assert_eq!(
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            1024
        );
        assert_eq!(u16::from_le_bytes([data[0x0c], data[0x0d]]), 10);
        assert_eq!(data[0x0e], 0xe0);
        // The two tag headers: the length of a key and the type code.
        assert_eq!(
            u16::from_le_bytes([data[1536 + 0x0c], data[1536 + 0x0d]]),
            148
        );
        assert_eq!(data[1536 + 0x0e], 0x68);
        assert_eq!(
            u16::from_le_bytes([data[3072 + 0x0c], data[3072 + 0x0d]]),
            20
        );
        assert_eq!(data[3072 + 0x0e], 0x68);
        // The chain of leaves of the first tag's tree: 4608, 5120 and 5632
        // are linked to one another.
        let siblings = |at: usize| {
            (
                u32::from_le_bytes([data[at + 4], data[at + 5], data[at + 6], data[at + 7]]),
                u32::from_le_bytes([data[at + 8], data[at + 9], data[at + 10], data[at + 11]]),
            )
        };
        assert_eq!(siblings(4608), (5120, 5632));
        assert_eq!(siblings(5120), (0xffff_ffff, 4608));
        assert_eq!(siblings(5632), (4608, 0xffff_ffff));
        // Every leaf: the widths of the three packed fields add up to the
        // length of one entry, and the space the header says is free is the
        // space the entries and the keys do not take.
        for (offset, keys, key_len) in [
            (1024usize, 2u16, 10usize),
            (4096, 57, 20),
            (4608, 18, 148),
            (5120, 22, 148),
            (5632, 17, 148),
        ] {
            let node = CdxNode::read(&data, offset).expect("a node");
            let leaf = node.leaf.as_ref().expect("a leaf");
            assert_eq!(node.keys, keys, "the number of keys of the leaf");
            assert_eq!(
                leaf.info_len * 8,
                (leaf.record_bits + leaf.dup_bits + leaf.trail_bits) as usize,
                "the widths of the fields of an entry"
            );
            assert_eq!(leaf.record_mask, (1u32 << leaf.record_bits) - 1);
            let read = cdx_leaf_keys(&data, &node, leaf, key_len).expect("the keys of the leaf");
            assert_eq!(read.len(), node.keys as usize);
            // The bytes the keys store in the heap: every key holds only
            // what differs from the key before it.
            let mut stored = 0usize;
            for index in 0..node.keys as usize {
                let entry = cdx_entry(&data, &node, leaf, index).expect("an entry");
                stored += key_len - entry.dup as usize - entry.trail as usize;
            }
            assert_eq!(
                leaf.free_space as usize,
                CDX_BLOCK - CDX_LEAF_HEADER - keys as usize * leaf.info_len - stored,
                "the free space of the leaf"
            );
        }
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn every_compound_index_of_the_corpus_is_read() {
        // The other three compound indexes of the corpus -- the ones that
        // came with the block -- are read here, because a fixture that no
        // test opens is a fixture that catches nothing: the tag directory
        // and the leaf code could break and these files would not notice.
        for (name, tags, rows) in [
            ("expense categories.CDX", 1, 5),
            ("expense details.CDX", 3, 6),
            ("expense reports.CDX", 3, 3),
        ] {
            let path = foxpro_path(name);
            let data = foxpro_fixture(name);
            let out = match Foxpro.extract(&data, &path).expect("a compound index") {
                Outcome::Text(t) => String::from_utf8(t).unwrap(),
                _ => panic!("text"),
            };
            let counted = out.matches("\ntag ").count();
            assert_eq!(counted, tags, "{name} holds {counted} tags:\n{out}");
            // Every tag says how many rows it points at, and the same
            // number of rows is named under it.
            for line in out.lines().filter(|l| l.starts_with("  rows: ")) {
                let n: usize = line
                    .trim_start_matches("  rows: ")
                    .parse()
                    .unwrap_or_else(|_| panic!("{name}: {line}"));
                assert_eq!(n, rows, "{name} says {n} rows:\n{out}");
            }
            // The keys are named, and the rows they point at are the
            // values of the rows they point at.
            assert!(out.contains("row 1:"), "{name} names no row:\n{out}");
        }
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn a_compound_index_of_a_table_holds_every_tag() {
        // A `.cdx` beside a table is the same shape as the `.dcx` beside a
        // container, and it holds more than one tag: the five tags of the
        // employees' index are named, each one says what its keys are, and
        // every one of them points at the rows of the table.
        let path = foxpro_path("employees.CDX");
        let data = foxpro_fixture("employees.CDX");
        let out = match Foxpro.extract(&data, &path).expect("a compound index") {
            Outcome::Text(t) => String::from_utf8(t).unwrap(),
            _ => panic!("text"),
        };
        for name in [
            "DEPARTMENT",
            "EMAILNAME",
            "LASTNAME",
            "POSTALCODE",
            "PRIMARYKEY",
        ] {
            assert!(out.contains(&format!(": {name}\n")), "{out}");
        }
        assert!(out.contains("key expression: departmentname\n"), "{out}");
        assert!(out.contains("key expression: employeeid\n"), "{out}");
        assert!(out.contains("key length: 50 bytes"), "{out}");
        assert!(out.contains("key length: 4 bytes"), "{out}");
        // The keys are the values of the rows: the departments of the
        // table, and the primary key, which is a number and is given as
        // the bytes it is.
        assert!(out.contains("row 3: \"Marketing\""), "{out}");
        assert!(out.contains("row 1: \"Sales\""), "{out}");
        assert!(out.contains("row 1: 0x80000001"), "{out}");
        assert!(out.contains("rows: 3"), "{out}");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn a_file_that_is_not_a_compound_index_is_declined() {
        // The reader claims the extension, so it has to say why it will not
        // read the file.
        assert!(Foxpro.extract(&vec![0u8; 1024], "x.dcx").is_err());
        assert!(Foxpro.extract(&vec![0u8; 1024], "x.cdx").is_err());
        // The container is not an index, even though it is beside one.
        let dbc = foxpro_fixture("EXPENSES.DBC");
        assert!(Foxpro.extract(&dbc, "x.dcx").is_err());
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn the_container_goes_to_the_reader_that_has_its_memo_file() {
        // Registration order is meaningful: the first candidate wins, so
        // the reader that looks for the memo file beside the container has
        // to be asked before the one that does not.
        let reg = rgx_core::Registry::new(crate::adapters());
        let names: Vec<&str> = reg
            .candidates_for_path("sales.dbc")
            .map(|a| a.name())
            .collect();
        assert_eq!(names.first(), Some(&"foxpro"), "{names:?}");
        assert!(names.contains(&"dbf"), "{names:?}");
    }

    #[test]
    #[cfg(feature = "foxpro")]
    fn foxpro_never_panics_on_arbitrary_bytes() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("container", foxpro_fixture("EXPENSES.DBC")),
                ("memo", foxpro_fixture("EXPENSES.DCT")),
                ("index", foxpro_fixture("EXPENSES.DCX")),
                ("empty", vec![]),
                ("zeros", vec![0u8; 1024]),
            ],
            200,
            "foxpro",
            |data| {
                let _ = Foxpro.extract(data, "nowhere/x.dbc");
                let _ = Foxpro.extract(data, "nowhere/x.dct");
                let _ = Foxpro.extract(data, "nowhere/x.dcx");
            },
        );
    }
}
