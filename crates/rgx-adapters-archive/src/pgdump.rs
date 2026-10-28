// SPDX-License-Identifier: Apache-2.0
//
// The framing and the metadata below were learned from PostgreSQL's own
// `pg_dump` implementation, which is the description of the format that
// exists; the code here is rgx's own. The provenance is recorded in
// `NOTICE`.

//! PostgreSQL's custom dump archive — the file `pg_dump -Fc` writes.
//!
//! **What it is.** A custom dump is a container: a common header, a table
//! of contents, and then one data block per table that has rows. ripgrep
//! reads none of it and the rows are the whole point of a dump, so this is
//! a [`Reach::Reveal`] reader — the bytes on disk are not text at all.
//!
//! **Where the layout comes from.** Every position below follows
//! PostgreSQL's own source — `src/bin/pg_dump/pg_backup_archiver.{c,h}`
//! for the common header and the table of contents, `src/bin/pg_dump/
//! pg_backup_custom.c` for the block framing — and not from a description
//! of it, because both the integers and the block framing are places where
//! a reader can be *nearly* right and still desync on the second entry.
//!
//! **The three things that are load-bearing.**
//!
//! 1. *Integers are sign-magnitude, not two's complement.* `WriteInt` writes
//!    a sign byte and then the magnitude, little-endian, a byte at a time.
//!    A reader that treats them as two's complement decodes a length of 3
//!    as -1 and stops.
//! 2. *The archive version gates the fields.* The header grew a byte at a
//!    time over fifteen releases and the table of contents grew with it:
//!    the relation kind only exists from 1.16, the table access method
//!    only from 1.14, the namespace only from 1.6, the dependency list
//!    only from 1.5. Reading a 1.15 archive as a 1.16 one puts every entry
//!    a field out of place, and the TOC then names tables that do not
//!    exist.
//! 3. *A data block is a run of length-prefixed chunks.* The compressed
//!    bytes are chopped into chunks, each written as an integer length and
//!    then that many bytes, and a zero length ends the block. That framing
//!    is what delimits the compressed stream, so the decompressor is handed
//!    exactly the bytes of one block and not one byte more.
//!
//! **What is refused rather than guessed.** A file that does not start
//! with `PGDMP` is not this format and is declined, so an SVN dump or a
//! plain SQL script falls through untouched. A file that starts with
//! `PGDMP` but names another archive format is declined by name as well —
//! the directory format's `toc.dat` starts with the same five bytes and
//! names the tar format, and reading it as a custom archive would invent
//! a table of contents that is not there. A compression algorithm this
//! reader does not have is refused, not passed through as noise.
//!
//! **What the other dump formats are.** A *plain* dump (`-Fp`) is a SQL
//! script: text, which ripgrep reads perfectly, so rgx does not claim it.
//! A *directory* dump (`-Fd`) is a directory of per-table files plus a
//! `toc.dat`; the per-table files are gzip streams that the decompress
//! adapter already opens, and only the schema lives in the `toc.dat` this
//! reader declines. A *tar* dump (`-Ft`) is a tar archive of that same
//! directory, so the tar adapter already walks it.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use rgx_core::compress::{ZlibDecoder, ZstdDecoder};
use rgx_core::{bail, decline, Adapter, Outcome, Result};

use crate::lz4::Lz4Decoder;

/// The five bytes every custom archive starts with.
const MAGIC: &[u8; 5] = b"PGDMP";

/// `ArchiveFormat` from `pg_backup.h`. Only the custom format is a single
/// self-contained file: the tar format is 3 and the directory format 5,
/// and both of those share this magic.
const FORMAT_CUSTOM: u8 = 1;

/// Block types, from `pg_backup_archiver.h`.
const BLK_DATA: u8 = 1;
const BLK_BLOBS: u8 = 3;

/// The compression algorithms, from `pg_compress_specification`. The values
/// were read out of real archives written by `pg_dump --compress=`, one
/// per algorithm, because the enum is not in a header this reader can see.
const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_GZIP: u8 = 1;
const COMPRESSION_LZ4: u8 = 2;
const COMPRESSION_ZSTD: u8 = 3;

/// How many bytes one decompressed table may emit. A dump of a wide table
/// is a real file; a dump that expands to a gigabyte out of a few
/// kilobytes is a bomb, and the two are told apart by the cap rather than
/// by hope.
const MAX_BLOCK_BYTES: u64 = 256 << 20;

/// How many bytes the whole listing may emit.
const MAX_TOTAL_BYTES: u64 = 512 << 20;

/// The archive version, encoded the way PostgreSQL encodes it:
/// `MAKE_ARCHIVE_VERSION(major, minor, rev) = ((major * 256 + minor) * 256 + rev)`.
/// Keeping the same encoding means the comparisons in the C source carry
/// over untranslated, and the gates below can be read next to the C ones.
const fn version(major: u32, minor: u32) -> u32 {
    (major * 256 + minor) * 256
}

const V1_0: u32 = version(1, 0);
const V1_2: u32 = version(1, 2);
const V1_3: u32 = version(1, 3);
const V1_4: u32 = version(1, 4);
const V1_5: u32 = version(1, 5);
const V1_6: u32 = version(1, 6);
const V1_7: u32 = version(1, 7);
const V1_8: u32 = version(1, 8);
const V1_9: u32 = version(1, 9);
const V1_10: u32 = version(1, 10);
const V1_11: u32 = version(1, 11);
const V1_14: u32 = version(1, 14);
const V1_15: u32 = version(1, 15);
const V1_16: u32 = version(1, 16);

/// The newest archive this reader accepts: PostgreSQL's own `K_VERS_MAX`,
/// which is 1.16 with any revision.
const V_MAX: u32 = V1_16 + 255;

/// Read one PostgreSQL integer at `p`: a sign byte, then `int_size` bytes
/// of little-endian magnitude.
///
/// Not two's complement — `WriteInt` writes the sign separately and
/// shifts the magnitude right, so `-1` is `01 01 00 00 00` and not
/// `FF FF FF FF`.
fn int_at(d: &[u8], p: &mut usize, int_size: usize) -> Result<i64> {
    let sign = *d
        .get(*p)
        .ok_or_else(|| rgx_core::anyhow!("pgdump: the archive ends inside a field"))?;
    *p += 1;
    let mut v: i64 = 0;
    for b in 0..int_size {
        let byte = *d
            .get(*p)
            .ok_or_else(|| rgx_core::anyhow!("pgdump: the archive ends inside a field"))?;
        *p += 1;
        v |= (byte as i64) << (b * 8);
    }
    // `wrapping_neg` because a sign-magnitude magnitude of 2^63 has no
    // positive other side: the file can name it, `i64` cannot hold it, and
    // a debug build must not die on the negation.
    Ok(if sign != 0 { v.wrapping_neg() } else { v })
}

/// A cursor over the archive, with the two widths the header declares.
struct Reader<'a> {
    d: &'a [u8],
    p: usize,
    int_size: usize,
    off_size: usize,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self {
            d,
            p: 0,
            int_size: 4,
            off_size: 8,
        }
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self
            .d
            .get(self.p)
            .ok_or_else(|| rgx_core::anyhow!("pgdump: the archive ends inside a field"))?;
        self.p += 1;
        Ok(b)
    }

    fn int(&mut self) -> Result<i64> {
        int_at(self.d, &mut self.p, self.int_size)
    }

    /// A string: its length as an integer, then the bytes. A negative
    /// length is a null string, which is how the dependency list ends.
    fn string(&mut self) -> Result<Option<&'a [u8]>> {
        let n = self.int()?;
        if n < 0 {
            return Ok(None);
        }
        let n = n as usize;
        let end = self
            .p
            .checked_add(n)
            .ok_or_else(|| rgx_core::anyhow!("pgdump: a string length overflows the archive"))?;
        if end > self.d.len() {
            bail!("pgdump: a string runs past the end of the archive");
        }
        let s = &self.d[self.p..end];
        self.p = end;
        Ok(Some(s))
    }

    /// A file offset: a state byte, then `off_size` little-endian bytes.
    fn offset(&mut self) -> Result<(u8, u64)> {
        let state = self.byte()?;
        let mut v: u64 = 0;
        for b in 0..self.off_size {
            let byte = self.byte()?;
            if b < 8 {
                v |= (byte as u64) << (b * 8);
            } else if byte != 0 {
                // The C reader refuses an offset that does not fit rather
                // than wrapping it, and so does this one.
                bail!("pgdump: a file offset in the archive is too large");
            }
        }
        Ok((state, v))
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The common header every archive format shares.
struct Header {
    version: u32,
    compression: u8,
    dbname: Option<String>,
    server: Option<String>,
    dumper: Option<String>,
}

fn read_header(r: &mut Reader) -> Result<Header> {
    if r.d.len() < MAGIC.len() || &r.d[..MAGIC.len()] != MAGIC {
        decline!("not a pg_dump archive (no PGDMP magic)");
    }
    r.p = MAGIC.len();
    let major = r.byte()? as u32;
    let minor = r.byte()? as u32;
    // The revision byte only exists from 1.1 on; before that it was implied.
    let revision = if major > 1 || (major == 1 && minor > 0) {
        r.byte()? as u32
    } else {
        0
    };
    let version = version(major, minor) + revision;
    if !(V1_0..=V_MAX).contains(&version) {
        bail!("pgdump: archive version {major}.{minor}.{revision} is not one this reader knows");
    }
    r.int_size = r.byte()? as usize;
    if r.int_size == 0 || r.int_size > 8 {
        bail!(
            "pgdump: an integer width of {} bytes is not representable",
            r.int_size
        );
    }
    // The offset width arrived in 1.7; before that an offset was an
    // integer, so the two widths were the same number.
    r.off_size = if version >= V1_7 {
        r.byte()? as usize
    } else {
        r.int_size
    };
    if r.off_size == 0 {
        bail!("pgdump: the archive declares a zero-byte file offset");
    }
    let format = r.byte()?;
    if format != FORMAT_CUSTOM {
        decline!("pgdump: the archive names format {format}, not the custom format");
    }
    // From 1.15 the header names the compression algorithm; before that it
    // carried a level, and a non-zero level meant gzip.
    let compression = if version >= V1_15 {
        r.byte()?
    } else if version >= V1_2 {
        let level = if version < V1_4 {
            r.byte()? as i64
        } else {
            r.int()?
        };
        if level != 0 {
            COMPRESSION_GZIP
        } else {
            COMPRESSION_NONE
        }
    } else {
        COMPRESSION_GZIP
    };
    if version >= V1_4 {
        // The creation date: seven integers, and the archive's own idea of
        // what time it is. Nothing downstream reads it.
        for _ in 0..7 {
            r.int()?;
        }
    }
    let dbname = if version >= V1_4 {
        r.string()?.map(text)
    } else {
        None
    };
    let (server, dumper) = if version >= V1_10 {
        (r.string()?.map(text), r.string()?.map(text))
    } else {
        (None, None)
    };
    Ok(Header {
        version,
        compression,
        dbname,
        server,
        dumper,
    })
}

/// One table-of-contents entry.
struct Toc {
    dump_id: i64,
    tag: String,
    desc: String,
    defn: Option<String>,
    copy_stmt: Option<String>,
    namespace: Option<String>,
}

fn read_toc(r: &mut Reader, version: u32) -> Result<Vec<Toc>> {
    let count = r.int()?;
    if !(0..=1_000_000).contains(&count) {
        bail!("pgdump: the table of contents claims {count} entries");
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let dump_id = r.int()?;
        let _had_dumper = r.int()?;
        if version >= V1_8 {
            r.string()?; // the catalog's table oid
        }
        r.string()?; // the object's oid
        let tag = r.string()?.map(text).unwrap_or_default();
        let desc = r.string()?.map(text).unwrap_or_default();
        if version >= V1_11 {
            r.int()?; // the section
        }
        let defn = r.string()?.map(text);
        r.string()?; // the drop statement
        let copy_stmt = if version >= V1_3 {
            r.string()?.map(text)
        } else {
            None
        };
        let namespace = if version >= V1_6 {
            r.string()?.map(text)
        } else {
            None
        };
        if version >= V1_10 {
            r.string()?; // the tablespace
        }
        if version >= V1_14 {
            r.string()?; // the table access method
        }
        if version >= V1_16 {
            r.int()?; // the relation kind
        }
        r.string()?; // the owner
        if version >= V1_9 {
            r.string()?; // the with-oids marker
        }
        if version >= V1_5 {
            // The dependency list, terminated by a null string.
            while r.string()?.is_some() {}
        }
        r.offset()?; // where the data block is
        if version < V1_7 {
            r.int()?; // the data size, before the offsets existed
        }
        out.push(Toc {
            dump_id,
            tag,
            desc,
            defn,
            copy_stmt,
            namespace,
        });
    }
    Ok(out)
}

/// A data block: where it is and the chunks its compressed payload is made
/// of.
struct Block {
    kind: u8,
    dump_id: i64,
    /// The chunk ranges, in order, of the compressed payload.
    chunks: Vec<(usize, usize)>,
    /// The large objects of a blob block, each with its own chunks.
    blobs: Vec<(i64, Vec<(usize, usize)>)>,
}

/// The chunks of one compressed payload: a length, then that many bytes,
/// over and over, until a zero length.
fn read_chunks(d: &[u8], p: &mut usize, int_size: usize) -> Result<Vec<(usize, usize)>> {
    let mut chunks = Vec::new();
    loop {
        let len = int_at(d, p, int_size)?;
        if len == 0 {
            return Ok(chunks);
        }
        if len < 0 {
            bail!("pgdump: a chunk claims a negative length");
        }
        let len = len as usize;
        let end = p
            .checked_add(len)
            .ok_or_else(|| rgx_core::anyhow!("pgdump: a chunk length overflows the archive"))?;
        if end > d.len() {
            bail!("pgdump: a chunk runs past the end of the archive");
        }
        chunks.push((*p, end));
        *p = end;
    }
}

/// Walk the data blocks that follow the table of contents.
fn read_blocks(d: &[u8], mut p: usize, int_size: usize) -> Result<Vec<Block>> {
    let mut blocks = Vec::new();
    while p < d.len() {
        let kind = d[p];
        p += 1;
        let dump_id = int_at(d, &mut p, int_size)?;
        match kind {
            BLK_DATA => {
                let chunks = read_chunks(d, &mut p, int_size)?;
                blocks.push(Block {
                    kind,
                    dump_id,
                    chunks,
                    blobs: Vec::new(),
                });
            }
            BLK_BLOBS => {
                // A blob block is a run of large objects, each with its own
                // compressed payload, and a zero oid ends the run.
                let mut blobs = Vec::new();
                loop {
                    let oid = int_at(d, &mut p, int_size)?;
                    if oid == 0 {
                        break;
                    }
                    let chunks = read_chunks(d, &mut p, int_size)?;
                    blobs.push((oid, chunks));
                }
                blocks.push(Block {
                    kind,
                    dump_id,
                    chunks: Vec::new(),
                    blobs,
                });
            }
            other => bail!("pgdump: unknown data block type {other}"),
        }
    }
    Ok(blocks)
}

/// Decompress one block's payload with the algorithm the header names.
///
/// The second value of the pair is true when the byte budget stopped the
/// decode, which is a different answer from a block that decoded whole.
fn decompress(header: &Header, comp: &[u8]) -> Result<(Vec<u8>, bool)> {
    match header.compression {
        COMPRESSION_NONE => Ok((comp.to_vec(), false)),
        COMPRESSION_GZIP => {
            // PostgreSQL's "gzip" is zlib's deflate under RFC 1950 framing,
            // not RFC 1952: `compress_gzip.c` calls `deflateInit` with the
            // default window, and the default window is a zlib wrapper.
            let (bounded, _consumed) = ZlibDecoder::new()
                .decode_bounded_with_consumed(comp, MAX_BLOCK_BYTES)
                .map_err(|e| rgx_core::anyhow!("pgdump: the zlib stream does not decode: {e}"))?;
            Ok((bounded.bytes, bounded.capped))
        }
        COMPRESSION_LZ4 => {
            let bounded = Lz4Decoder::new()
                .decode_bounded(comp, MAX_BLOCK_BYTES)
                .map_err(|e| rgx_core::anyhow!("pgdump: the lz4 frame does not decode: {e}"))?;
            Ok((bounded.bytes, bounded.capped))
        }
        COMPRESSION_ZSTD => {
            let bounded = ZstdDecoder::new()
                .decode_bounded(comp, MAX_BLOCK_BYTES)
                .map_err(|e| rgx_core::anyhow!("pgdump: the zstd frame does not decode: {e}"))?;
            Ok((bounded.bytes, bounded.capped))
        }
        other => bail!("pgdump: compression algorithm {other} is not one this reader has"),
    }
}

/// How many rows a decompressed payload holds: every line but the `\.` that
/// ends a COPY block.
fn count_rows(payload: &[u8]) -> usize {
    let mut rows = 0usize;
    for line in payload.split(|b| *b == b'\n') {
        if line.is_empty() || line == b"\\." {
            continue;
        }
        rows += 1;
    }
    rows
}

/// A large object as lines, when it is text, and as a size when it is not.
///
/// A large object in a dump is usually a picture, and a search tool wants
/// the words in the one that is a document. Bytes that are not text are
/// described rather than dumped: a binary payload printed as text is
/// noise that displaces the answer.
fn emit_blob(out: &mut String, oid: i64, payload: &[u8]) {
    let is_text = payload
        .iter()
        .all(|b| *b == b'\n' || *b == b'\t' || (*b >= 0x20 && *b < 0x7f));
    if is_text {
        let _ = writeln!(out, "large object {oid}");
        let text = String::from_utf8_lossy(payload);
        for line in text.lines() {
            let _ = writeln!(out, "{line}");
        }
    } else {
        let _ = writeln!(out, "large object {oid}: {} bytes", payload.len());
    }
}

pub struct PgDump;
impl Adapter for PgDump {
    fn name(&self) -> &'static str {
        "pgdump"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["dump", "pgdump"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let mut r = Reader::new(data);
        let header = read_header(&mut r)?;
        let toc = read_toc(&mut r, header.version)?;
        let blocks = read_blocks(data, r.p, r.int_size)?;

        let mut out = String::new();
        let _ = writeln!(
            out,
            "pgdump custom archive {}.{}",
            header.version >> 16,
            header.version >> 8 & 255
        );
        if let Some(db) = &header.dbname {
            let _ = writeln!(out, "database: {db}");
        }
        if let Some(server) = &header.server {
            let _ = writeln!(out, "server: {server}");
        }
        if let Some(dumper) = &header.dumper {
            let _ = writeln!(out, "dumper: {dumper}");
        }
        let _ = writeln!(
            out,
            "compression: {}",
            match header.compression {
                COMPRESSION_NONE => "none",
                COMPRESSION_GZIP => "gzip",
                COMPRESSION_LZ4 => "lz4",
                COMPRESSION_ZSTD => "zstd",
                other => {
                    let _ = writeln!(
                        out,
                        "compression algorithm {other} is not one this reader has"
                    );
                    return Ok(Outcome::Text(out.into_bytes()));
                }
            }
        );
        let _ = writeln!(out, "entries: {}", toc.len());

        let mut tables = 0usize;
        let mut rows = 0usize;
        let mut body = String::new();

        // The block of an entry is found by dump id, and a linear scan per
        // entry is quadratic in a table of contents the header allows to
        // run to a million entries. Bucketed once, the lookup walks only
        // the blocks that share an id, and the first of them is the one
        // the scan used to find.
        let mut blocks_by_id: BTreeMap<i64, Vec<&Block>> = BTreeMap::new();
        for b in &blocks {
            blocks_by_id.entry(b.dump_id).or_default().push(b);
        }

        'entries: for entry in &toc {
            // The aggregate cap is enforced as the blocks arrive, not once
            // they have all been held: `body` used to accumulate every
            // block's payload before the check, which is the shape the
            // per-block cap exists to prevent. The truncation note is the
            // one the final check writes.
            if body.len() > MAX_TOTAL_BYTES as usize {
                break;
            }
            let name = match &entry.namespace {
                Some(ns) if !ns.is_empty() => format!("{ns}.{}", entry.tag),
                _ => entry.tag.clone(),
            };
            let block = blocks_by_id
                .get(&entry.dump_id)
                .and_then(|same| same.first().copied());
            if let Some(defn) = &entry.defn {
                // The definition and the COPY statement are SQL fragments
                // that end in a newline of their own, so they are trimmed
                // before being written: the newline that follows them is
                // this reader's, and two of them put a blank line between
                // the statement and the rows it introduces.
                let defn = defn.trim_end_matches('\n');
                if !defn.trim().is_empty() {
                    let _ = writeln!(body, "-- {name} ({})", entry.desc);
                    let _ = writeln!(body, "{defn}");
                    let _ = writeln!(body);
                }
            }
            let Some(block) = block else { continue };
            if block.kind == BLK_BLOBS {
                let _ = writeln!(body, "-- {name} ({})", entry.desc);
                for (oid, chunks) in &block.blobs {
                    let mut comp = Vec::new();
                    for (s, e) in chunks {
                        comp.extend_from_slice(&data[*s..*e]);
                    }
                    let (payload, _capped) = decompress(&header, &comp)?;
                    emit_blob(&mut body, *oid, &payload);
                    // One entry may hold any number of blobs, and each is
                    // capped on its own: the aggregate is checked here too
                    // or one entry alone could pass the per-block cap N
                    // times.
                    if body.len() > MAX_TOTAL_BYTES as usize {
                        break 'entries;
                    }
                }
                let _ = writeln!(body);
                continue;
            }
            if block.kind != BLK_DATA {
                continue;
            }
            tables += 1;
            let mut comp = Vec::new();
            for (s, e) in &block.chunks {
                comp.extend_from_slice(&data[*s..*e]);
            }
            let (payload, capped) = decompress(&header, &comp)?;
            rows += count_rows(&payload);
            let _ = writeln!(body, "-- {name} ({})", entry.desc);
            if let Some(copy) = &entry.copy_stmt {
                let copy = copy.trim_end_matches('\n');
                if !copy.trim().is_empty() {
                    let _ = writeln!(body, "{copy}");
                }
            }
            if capped {
                let _ = writeln!(body, "-- (truncated at {MAX_BLOCK_BYTES} bytes)");
            }
            let text = String::from_utf8_lossy(&payload);
            for line in text.lines() {
                let _ = writeln!(body, "{line}");
            }
            let _ = writeln!(body);
        }

        let _ = writeln!(out, "tables: {tables}");
        let _ = writeln!(out, "rows: {rows}");
        let _ = writeln!(out);
        out.push_str(&body);

        if out.len() as u64 > MAX_TOTAL_BYTES {
            out.truncate(MAX_TOTAL_BYTES as usize);
            let _ = writeln!(out, "-- (listing truncated at {MAX_TOTAL_BYTES} bytes)");
        }
        Ok(Outcome::Text(out.into_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn text_of(out: Outcome) -> String {
        match out {
            Outcome::Text(t) => String::from_utf8_lossy(&t).into_owned(),
            _ => panic!("expected Text"),
        }
    }

    /// A minimal archive: the header, one table of contents entry, and one
    /// data block. Written by hand here because the *fixtures* are real
    /// `pg_dump` output, and this is only the shape the reader walks.
    fn hand_made(entries: &[(&str, &str)], rows: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(MAGIC);
        d.push(1); // major
        d.push(15); // minor
        d.push(0); // revision
        d.push(4); // int size
        d.push(8); // offset size
        d.push(FORMAT_CUSTOM);
        d.push(COMPRESSION_NONE);
        for v in [0i64, 0, 0, 1, 9, 126, 0] {
            d.push(0); // sign
            d.extend_from_slice(&(v as u32).to_le_bytes());
        }
        for s in ["db", "16.15", "16.15"] {
            d.push(0);
            d.extend_from_slice(&(s.len() as u32).to_le_bytes());
            d.extend_from_slice(s.as_bytes());
        }
        d.push(0);
        d.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, (tag, _)) in entries.iter().enumerate() {
            d.push(0);
            d.extend_from_slice(&((i as u32) + 1).to_le_bytes()); // dump id
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // had dumper
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // table oid
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // oid
            d.push(0);
            d.extend_from_slice(&(tag.len() as u32).to_le_bytes());
            d.extend_from_slice(tag.as_bytes());
            d.push(0);
            d.extend_from_slice(&8u32.to_le_bytes()); // desc
            d.extend_from_slice(b"TABLE   ");
            d.push(0);
            d.extend_from_slice(&1u32.to_le_bytes()); // section
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // defn
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // drop stmt
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // copy stmt
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // namespace
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // tablespace
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // tableam
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // owner
            d.push(0);
            d.extend_from_slice(&0u32.to_le_bytes()); // with oids
            d.push(1); // a null string ends the dependency list
            d.extend_from_slice(&1u32.to_le_bytes());
            d.push(3); // offset state: no data
            d.extend_from_slice(&0u64.to_le_bytes());
        }
        d.push(BLK_DATA);
        d.push(0);
        d.extend_from_slice(&1u32.to_le_bytes()); // dump id
        d.push(0);
        d.extend_from_slice(&(rows.len() as u32).to_le_bytes());
        d.extend_from_slice(rows);
        d.push(0);
        d.extend_from_slice(&0u32.to_le_bytes());
        d
    }

    #[test]
    fn a_file_without_the_magic_is_declined() {
        let e = PgDump.extract(b"SQLite format 3\0", "x.dump");
        assert!(e.is_err(), "a file that is not a dump must be declined");
    }

    #[test]
    fn the_directory_formats_toc_is_declined_by_name() {
        // The directory format's `toc.dat` starts with the same five bytes
        // and names the tar format; reading it as a custom archive would
        // invent a table of contents that is not there.
        let mut d = Vec::new();
        d.extend_from_slice(MAGIC);
        d.extend_from_slice(&[1, 15, 0, 4, 8, 3]);
        let e = PgDump.extract(&d, "toc.dat");
        assert!(e.is_err(), "the directory format must be declined");
    }

    #[test]
    fn a_hand_made_archive_is_walked() {
        let d = hand_made(&[("clientes", "")], b"1\tAna\n2\tBruno\n");
        let out = text_of(PgDump.extract(&d, "x.dump").expect("dump"));
        assert!(out.contains("pgdump custom archive 1.15"), "{out}");
        assert!(out.contains("database: db"), "{out}");
        assert!(out.contains("1\tAna"), "{out}");
        assert!(out.contains("tables: 1"), "{out}");
        assert!(out.contains("rows: 2"), "{out}");
    }

    /// The real archives, one per compression algorithm `pg_dump` can
    /// write, and the rows `pg_restore` prints for them.
    ///
    /// The expected file is not retyped: it is the `pg_restore -a` output,
    /// taken from the tool itself, so the bytes the reader has to produce
    /// are the bytes PostgreSQL wrote.
    const FIXTURES: &[(&str, &[u8])] = &[
        (
            "pgdump_gzip.dump",
            include_bytes!("../testdata/pgdump_gzip.dump"),
        ),
        (
            "pgdump_gzip9.dump",
            include_bytes!("../testdata/pgdump_gzip9.dump"),
        ),
        (
            "pgdump_lz4.dump",
            include_bytes!("../testdata/pgdump_lz4.dump"),
        ),
        (
            "pgdump_zstd.dump",
            include_bytes!("../testdata/pgdump_zstd.dump"),
        ),
        (
            "pgdump_none.dump",
            include_bytes!("../testdata/pgdump_none.dump"),
        ),
    ];

    #[test]
    fn every_compression_algorithm_decodes_to_the_rows_pg_restore_prints() {
        let expected = include_bytes!("../testdata/pgdump_expected.txt");
        // The expected file is two COPY blocks separated by a blank line.
        let expected = String::from_utf8_lossy(expected);
        let blocks: Vec<&str> = expected
            .split("\n\n")
            .map(|b| b.trim_end_matches('\n'))
            .filter(|b| !b.is_empty())
            .collect();
        assert_eq!(blocks.len(), 2, "the oracle holds two COPY blocks");

        for (name, dump) in FIXTURES {
            let out = text_of(PgDump.extract(dump, name).expect("dump"));
            for block in &blocks {
                assert!(
                    out.contains(block),
                    "{name} did not carry the rows pg_restore prints:\n{out}"
                );
            }
            assert!(out.contains("tables: 2"), "{name}: {out}");
            assert!(out.contains("rows: 5"), "{name}: {out}");
            assert!(out.contains("database: rgxtest"), "{name}: {out}");
            assert!(out.contains("server: 16.15"), "{name}: {out}");
        }
    }

    #[test]
    fn the_schema_of_the_archive_comes_through() {
        let dump = include_bytes!("../testdata/pgdump_gzip.dump");
        let out = text_of(PgDump.extract(dump, "x.dump").expect("dump"));
        assert!(out.contains("CREATE TABLE public.clientes"), "{out}");
        assert!(out.contains("CREATE INDEX clientes_nome"), "{out}");
        assert!(out.contains("ALTER TABLE ONLY public.clientes"), "{out}");
    }

    #[test]
    fn a_truncated_archive_is_refused_rather_than_half_read() {
        let dump = include_bytes!("../testdata/pgdump_gzip.dump");
        for cut in [5usize, 20, 100, 2000, 4000] {
            let e = PgDump.extract(&dump[..cut.min(dump.len())], "x.dump");
            assert!(e.is_err(), "a cut archive at {cut} must not decode");
        }
    }

    #[test]
    fn the_reader_never_panics_on_a_mutated_archive() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                (
                    "gzip",
                    include_bytes!("../testdata/pgdump_gzip.dump").to_vec(),
                ),
                (
                    "lz4",
                    include_bytes!("../testdata/pgdump_lz4.dump").to_vec(),
                ),
                (
                    "zstd",
                    include_bytes!("../testdata/pgdump_zstd.dump").to_vec(),
                ),
            ],
            200,
            "pgdump",
            |d| {
                let _ = PgDump.extract(d, "x.dump");
            },
        );
    }
}
