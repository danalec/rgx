// SPDX-License-Identifier: Apache-2.0

//! Alignment and variant containers: **BAM**, **BCF**, **CRAM**.
//!
//! All three are binary in the strong sense: a `.bam` is a BGZF stream whose
//! reference names and SAM header exist nowhere in the compressed bytes, so
//! `rg` over the file finds nothing and `rgx` finds the names a sequencing
//! search is actually for. Each adapter reports those names and states, in
//! its own output, what it did not decode.
//!
//! The text formats of the same family — FASTA/FASTQ, GFF/GTF, PDB,
//! mmCIF, VCF — are in [`crate::flatfiles`], and they are **rendered**, not
//! answered: `rg` already reads them, so an adapter that *revealed* them
//! would make rgx a subset of `rg`. A rendering is a different thing: the
//! default policy does not consult it, so the file's own bytes stay the
//! answer, and under `RGX_ADAPTER_VIEW=render` the records come out unwrapped and
//! with their fields separated by spaces. Text is not this module's job;
//! containers are.
//!
//! SAM is the one that needs the sentence qualified rather than absolute: a
//! plain `.sam` is that text and is declined, but a `.sam` written by
//! `samtools view --output-BGZF` is a container whose records `rg` cannot
//! see, and `Sam` inflates it. The line between the two is the `BC` extra
//! subfield, which is what the other adapters in this file already use to
//! tell a BGZF block from an ordinary gzip member.
//!
//! Layouts were read from the specifications, not recalled, and the
//! variable-length integers were cross-checked against htslib:
//!
//! * SAM/BAM + BGZF — <https://samtools.github.io/hts-specs/SAMv1.pdf>
//! * BCF 1 and 2 — <https://samtools.github.io/hts-specs/BCFv1_qref.pdf>,
//!   <https://samtools.github.io/hts-specs/BCFv2_qref.pdf>
//! * CRAM 2 and 3 — <https://samtools.github.io/hts-specs/CRAMv2.1.pdf>,
//!   <https://samtools.github.io/hts-specs/CRAMv3.pdf>
//! * `cram/cram_io.c` (`itf8_decode`, `ltf8_decode`, `cram_read_container`,
//!   `cram_read_block`) — <https://github.com/samtools/htslib>
//!
//! Where htslib and the CRAM spec tables disagree, htslib wins: the
//! container header carries an explicit `num_landmarks` count that the spec's
//! `array<itf8>` row does not name. What the CRAM 3 spec does say is
//! load-bearing too: the container's `length` is the size of its *blocks*,
//! the container header carries its own size, and the landmarks are the
//! block offsets within that region.

use alloc::boxed::Box;
use alloc::string::String;
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram", feature = "sam"))]
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt::Write as _;
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
use rgx_core::bail;
#[cfg(feature = "cram")]
use rgx_core::compress::crc32::crc32;
#[cfg(feature = "cram")]
use rgx_core::compress::Bzip2Decoder;
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram", feature = "sam"))]
use rgx_core::compress::GzipReader;
#[cfg(feature = "cram")]
use rgx_core::compress::XzReader;
use rgx_core::{decline, Adapter, Outcome, Result};

// ---------------------------------------------------------------------------
// Bounds. These containers may be larger than the machine; the report is
// not. Every bound is named in the output when it bites — a count that
// silently stops at a cap is a different claim from one that does not.
// ---------------------------------------------------------------------------

/// Inflated bytes one container may contribute. A BGZF block holds at most
/// 64 KiB, so this is 512 blocks: ample for any header plus the first
/// records, and nowhere near the multi-gigabyte file that would otherwise
/// allocate what the file spent compress.
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram", feature = "sam"))]
const MAX_INFLATE: u64 = 32 << 20;

/// BGZF blocks walked. The walk allocates nothing per block, but a
/// pathological file can declare far more blocks than a reader should
/// chase; the count stops growing and says so.
#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
const MAX_BGZF_BLOCKS: usize = 1 << 20;

/// Reference sequences whose name and length are held for the per-read
/// tally and printed. Beyond this the file still parses.
#[cfg(feature = "bam")]
const MAX_REFS_LISTED: usize = 4096;

/// Alignment records written out in full.
#[cfg(feature = "bam")]
const MAX_RECORDS_REPORTED: usize = 12;

/// Records scanned for the per-reference read tally, and distinct
/// references tallied. Both keep the tally linear on a crafted file whose
/// every record names a different reference.
#[cfg(feature = "bam")]
const MAX_TALLY_RECORDS: u64 = 100_000;
#[cfg(feature = "bam")]
const MAX_TALLY_REFS: usize = 256;

/// Reference names listed in the per-reference read tally.
#[cfg(any(feature = "bam", feature = "bcf"))]
const MAX_TALLY_SHOWN: usize = 8;

/// CRAM containers walked to total the alignment count.
#[cfg(feature = "cram")]
const MAX_CRAMS_CONTAINERS: usize = 4096;

/// Blocks and landmarks read from one CRAM container header.
#[cfg(feature = "cram")]
const MAX_CRAMS_BLOCKS: usize = 1024;
#[cfg(feature = "cram")]
const MAX_CRAMS_LANDMARKS: usize = 1 << 16;

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// BAM: BGZF-compressed alignment records plus the SAM header they refer to.
#[cfg(feature = "bam")]
pub struct BamAlign;
#[cfg(feature = "bam")]
impl Adapter for BamAlign {
    fn name(&self) -> &'static str {
        "bam"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bam"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_bam(data)?.into_bytes()))
    }
}

/// SAM records that are **compressed**, which is a different question from
/// SAM records that are text.
///
/// A plain `.sam` is line-oriented text that `rg` already reads, and it is
/// deliberately declined below: an adapter that answered for it would make
/// rgx a *subset* of `rg` under the default policy, which is the one thing
/// this crate is built not to do. But `samtools view --output-BGZF` writes a
/// `.sam` whose bytes are a BGZF stream, and `rg` over that file finds
/// nothing at all — the alignment records, the `@SQ` header lines and the
/// reference names exist nowhere in the compressed bytes. That is the same
/// situation as `.gz`, and the same answer: inflate it.
///
/// The test is the `BC` extra subfield, not the `1f 8b` magic. Both this
/// and a plain `gzip`ed SAM start with a gzip member, and only BGZF carries
/// the subfield that says where the block ends. A file without it is handed
/// to the ordinary gzip reader instead of to the block walk.
#[cfg(feature = "sam")]
pub struct Sam;
#[cfg(feature = "sam")]
impl Adapter for Sam {
    fn name(&self) -> &'static str {
        "sam"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["sam"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        if !GzipReader::is_gzip(data) {
            // Not a failure: this is the ordinary case, and declining is what
            // keeps the file searchable as the text it already is.
            decline!("sam: plain text, which rg reads directly; leaving the file to the raw path");
        }
        let mut out = String::new();
        let (raw, walk) = inflate_bgzf(data, MAX_INFLATE);
        if walk.blocks == 0 {
            // A gzip member with no `BC` subfield is a plain `gzip`, not
            // BGZF. The block walk correctly refuses to guess a boundary, so
            // the whole-member reader answers instead.
            let b = GzipReader::decode_bounded(data, MAX_INFLATE).map_err(rgx_core::Error::msg)?;
            out.push_str("sam (gzip-compressed, not BGZF)\n");
            if b.capped {
                let _ = writeln!(
                    out,
                    "note: the {MAX_INFLATE}-byte inflation ceiling stopped the decode"
                );
            }
            out.push_str(&String::from_utf8_lossy(&b.bytes));
            return Ok(Outcome::Text(out.into_bytes()));
        }
        out.push_str("sam (BGZF-compressed)\n");
        write_bgzf_summary(&mut out, &walk);
        if let Some(n) = &walk.note {
            let _ = writeln!(out, "note: {n}");
        }
        out.push_str(&String::from_utf8_lossy(&raw));
        Ok(Outcome::Text(out.into_bytes()))
    }
}

/// BCF: BGZF-compressed variant calls whose header carries the contig and
/// sample dictionaries.
#[cfg(feature = "bcf")]
pub struct BcfVariants;
#[cfg(feature = "bcf")]
impl Adapter for BcfVariants {
    fn name(&self) -> &'static str {
        "bcf"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["bcf"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_bcf(data)?.into_bytes()))
    }
}

/// CRAM: an uncompressed container stream whose header block holds the SAM
/// header and whose container headers hold the record counts.
#[cfg(feature = "cram")]
pub struct CramAlign;
#[cfg(feature = "cram")]
impl Adapter for CramAlign {
    fn name(&self) -> &'static str {
        "cram"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["cram"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        Ok(Outcome::Text(describe_cram(data)?.into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// Bounds-checked cursor. Every read into untrusted bytes goes through it:
// an adapter fed a crafted length field must bail, not panic.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

#[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
impl<'a> Cursor<'a> {
    #[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
    fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    #[cfg(any(feature = "bam", feature = "bcf"))]
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.at)
    }

    #[cfg(any(feature = "bam", feature = "cram"))]
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.at)?;
        self.at = self.at.checked_add(1)?;
        Some(v)
    }

    #[cfg(feature = "bam")]
    fn u16(&mut self) -> Option<u16> {
        let v = u16::from_le_bytes(self.take(2)?.try_into().ok()?);
        Some(v)
    }

    #[cfg(feature = "bam")]
    fn u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.take(4)?.try_into().ok()?);
        Some(v)
    }

    #[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
    fn i32(&mut self) -> Option<i32> {
        let v = i32::from_le_bytes(self.take(4)?.try_into().ok()?);
        Some(v)
    }

    #[cfg(feature = "bam")]
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    /// The returned slice borrows the *buffer*, never the cursor, so a
    /// caller may chain two reads without fighting the borrow checker.
    #[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// ITF-8 (CRAMv3 §10.1).
    #[cfg(feature = "cram")]
    fn itf8(&mut self) -> Option<i32> {
        let (v, n) = itf8_get(self.b.get(self.at..)?)?;
        self.at = self.at.checked_add(n)?;
        Some(v)
    }

    /// LTF-8, the same prefix scheme widened to eight bytes.
    #[cfg(feature = "cram")]
    fn ltf8(&mut self) -> Option<u64> {
        let (v, n) = ltf8_get(self.b.get(self.at..)?)?;
        self.at = self.at.checked_add(n)?;
        Some(v)
    }
}

/// ITF-8 decode: `(value, bytes consumed)`. `None` means the buffer ended
/// inside the value.
///
/// The first byte carries a prefix of one-bits and a zero, then the value's
/// high bits; the remaining bytes carry it big-endian. The 5-byte form is
/// the odd one — its last byte holds 4 bits, not 8, and it is masked with
/// `0x0f` before it is folded in. So `-1` has **two** spellings and both
/// decode to `-1`: `ff ff ff ff 0f`, and the five `ff`s of the CRAM 2.1
/// specification's own end-of-file listing (§8), which is the form htsjdk
/// writes for a v2 marker. A reader that admits only one of them refuses a
/// file the specification itself describes, so both are read here. A
/// leading `0xff` is therefore an ordinary 5-byte prefix, unlike in LTF-8.
#[cfg(feature = "cram")]
fn itf8_get(b: &[u8]) -> Option<(i32, usize)> {
    let first = *b.first()?;
    if first < 0x80 {
        return Some(((first as i32) & 0x7f, 1));
    }
    if first < 0xc0 {
        let rest = b.get(1..2)?;
        let v = (((first as i32) & 0x3f) << 8) | rest[0] as i32;
        return Some((v, 2));
    }
    if first < 0xe0 {
        let rest = b.get(1..3)?;
        let v = (((first as i32) & 0x1f) << 16) | ((rest[0] as i32) << 8) | rest[1] as i32;
        return Some((v, 3));
    }
    if first < 0xf0 {
        let rest = b.get(1..4)?;
        let v = (((first as i32) & 0x0f) << 24)
            | ((rest[0] as i32) << 16)
            | ((rest[1] as i32) << 8)
            | rest[2] as i32;
        return Some((v, 4));
    }
    // `0xff` is the 5-byte form here, not a reserved prefix: htslib
    // tabulates the width by the top nibble, and index 15 is five bytes.
    let rest = b.get(1..5)?;
    let v = (((first as i32) & 0x0f) << 28)
        | ((rest[0] as i32) << 20)
        | ((rest[1] as i32) << 12)
        | ((rest[2] as i32) << 4)
        | (rest[3] as i32 & 0x0f);
    Some((v, 5))
}

/// `(extra bytes after the first, mask of the first)` for LTF-8 by prefix.
/// Unlike ITF-8 every byte after the first is a full byte here, so the
/// shifts stay byte-aligned.
#[cfg(feature = "cram")]
const LTF8_SHAPES: [(usize, u64); 8] = [
    (0, 0x7f),
    (1, 0x3f),
    (2, 0x1f),
    (3, 0x0f),
    (4, 0x07),
    (5, 0x03),
    (6, 0x01),
    (7, 0x00),
];

#[cfg(feature = "cram")]
fn ltf8_get(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    if first == 0xff {
        return None; // reserved prefix
    }
    let (extra, mask) = if first < 0x80 {
        LTF8_SHAPES[0]
    } else if first < 0xc0 {
        LTF8_SHAPES[1]
    } else if first < 0xe0 {
        LTF8_SHAPES[2]
    } else if first < 0xf0 {
        LTF8_SHAPES[3]
    } else if first < 0xf8 {
        LTF8_SHAPES[4]
    } else if first < 0xfc {
        LTF8_SHAPES[5]
    } else if first < 0xfe {
        LTF8_SHAPES[6]
    } else {
        LTF8_SHAPES[7]
    };
    let bytes = b.get(..extra.checked_add(1)?)?;
    let mut val = ((first as u64) & mask) << (extra * 8);
    for (i, &byte) in bytes.iter().skip(1).enumerate() {
        val |= ((byte as u64) & 0xff) << ((extra - 1 - i) * 8);
    }
    Some((val, extra + 1))
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Lossy text out of a length-delimited byte range, cut at the first NUL.
/// BAM's header is NUL-*padded* to `l_text` and BCF2's is NUL-*terminated*;
/// neither length is where the string ends. Non-printable bytes other than
/// tab/newline/carriage return become `?`, so a crafted reference name
/// cannot inject control characters into the report.
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
fn cstring(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    let mut out = String::new();
    for &b in slice.get(..end).unwrap_or(&[]) {
        match b {
            b'\t' | b'\n' | b'\r' => out.push(b as char),
            0x20..=0x7e => out.push(b as char),
            _ => out.push('?'),
        }
    }
    out
}

/// Fenced text block, so an embedded header cannot be mistaken for part of
/// the report around it.
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram"))]
fn write_block(out: &mut String, label: &str, text: &str) {
    let _ = writeln!(out, "{label}:");
    for line in text.lines() {
        let _ = writeln!(out, "  {line}");
    }
    let _ = writeln!(out, "end {label}");
}

// ---------------------------------------------------------------------------
// BGZF. BAM and BCF are not gzip files that happen to be BGZF: a BGZF block
// is a complete gzip member carrying the RFC 1952 extra subfield `BC`, whose
// payload is the total block size minus one. That field is what makes block
// boundaries findable without decompressing, and its absence is what tells
// a BAM apart from a gzipped SAM.
// ---------------------------------------------------------------------------

/// SAMv1 §4.1 "End-of-file marker": the 28-byte empty BGZF block.
#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
const BGZF_EOF_MARKER: [u8; 28] = [
    0x1f, 0x8b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x06, 0x00, 0x42, 0x43, 0x02, 0x00,
    0x1b, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
struct BgzfWalk {
    blocks: usize,
    compressed_bytes: usize,
    inflated_bytes: usize,
    eof_marker: bool,
    note: Option<String>,
}

/// Total byte length of the gzip member at the front of `m`, from its BGZF
/// `BC` extra subfield. `None` when the member carries no such subfield —
/// the honest answer for a plain gzip file, and why the walk stops there
/// instead of guessing a boundary.
#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
fn bgzf_member_len(m: &[u8]) -> Option<usize> {
    if m.get(..3) != Some(&[0x1f, 0x8b, 0x08]) || m.len() < 18 {
        return None;
    }
    let flags = *m.get(3)?;
    let mut at = 10usize;
    if flags & 0x04 == 0 {
        return None;
    }
    let xlen = u16::from_le_bytes(m.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize;
    at = at.checked_add(2)?;
    let extra = m.get(at..at.checked_add(xlen)?)?;
    let mut p = 0usize;
    let mut bsize = None;
    // Bounded by the subfield's own 4-byte header, not by `get(p..)`:
    // that returns `Some(&[])` at the end of the buffer, and a subfield
    // walked off the end would take the whole file down with it.
    while p.checked_add(4).is_some_and(|end| end <= extra.len()) {
        let field = extra.get(p..)?;
        let si1 = *field.first()?;
        let si2 = *field.get(1)?;
        let slen = u16::from_le_bytes(field.get(2..4)?.try_into().ok()?) as usize;
        if si1 == b'B' && si2 == b'C' && slen == 2 {
            let data = field.get(4..4usize.checked_add(slen)?)?;
            bsize = Some(u16::from_le_bytes(data.try_into().ok()?) as usize + 1);
        }
        p = p.checked_add(4)?.checked_add(slen)?;
    }
    at = at.checked_add(xlen)?;
    bsize.filter(|&len| len >= at + 8)
}

/// Inflate a BGZF stream one block at a time.
///
/// Not one `GzipReader` call over the whole file, for two reasons that call
/// cannot serve: a truncated file must still yield the blocks that *were*
/// whole, and the block count the report states has to be the count
/// actually walked.
#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
fn inflate_bgzf(data: &[u8], max_bytes: u64) -> (Vec<u8>, BgzfWalk) {
    let mut out: Vec<u8> = Vec::new();
    let mut blocks = 0usize;
    let mut compressed_bytes = 0usize;
    let mut note = None;
    let mut at = 0usize;

    while at < data.len() {
        if blocks >= MAX_BGZF_BLOCKS {
            note = Some(format!(
                "block walk stopped at the {MAX_BGZF_BLOCKS}-block cap; the rest of the file was not read"
            ));
            break;
        }
        let Some(blen) = bgzf_member_len(&data[at..]) else {
            if at == 0 {
                note = Some("no BGZF block header: the `BC` extra subfield is missing".to_string());
            }
            break;
        };
        let end = at
            .checked_add(blen)
            .map_or(data.len(), |e| e.min(data.len()));
        let budget = max_bytes.saturating_sub(out.len() as u64);
        let Some(member) = data.get(at..end) else {
            note = Some(format!(
                "block {} runs past the end of the file",
                blocks + 1
            ));
            break;
        };
        match GzipReader::decode_bounded(member, budget) {
            Ok(chunk) => {
                if chunk.capped {
                    note = Some(format!(
                        "inflation stopped at the {max_bytes}-byte cap; counts below cover the inflated prefix only"
                    ));
                } else {
                    out.extend_from_slice(&chunk.bytes);
                }
                blocks += 1;
                compressed_bytes += end - at;
                at = end;
                if chunk.capped {
                    break;
                }
            }
            Err(e) => {
                note = Some(format!(
                    "block {} could not be inflated ({e}); the report covers the {blocks} block(s) before it",
                    blocks + 1
                ));
                break;
            }
        }
    }

    let walk = BgzfWalk {
        blocks,
        compressed_bytes,
        inflated_bytes: out.len(),
        eof_marker: data.len() >= BGZF_EOF_MARKER.len()
            && data.get(data.len() - BGZF_EOF_MARKER.len()..) == Some(&BGZF_EOF_MARKER[..]),
        note,
    };
    (out, walk)
}

#[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
fn write_bgzf_summary(out: &mut String, walk: &BgzfWalk) {
    let _ = writeln!(
        out,
        "bgzf: {} block(s), {} compressed byte(s) walked, {} inflated byte(s), 28-byte EOF marker {}",
        walk.blocks,
        walk.compressed_bytes,
        walk.inflated_bytes,
        if walk.eof_marker {
            "present"
        } else {
            "absent"
        }
    );
    if let Some(note) = &walk.note {
        let _ = writeln!(out, "bgzf: {note}");
    }
}

// ---------------------------------------------------------------------------
// BAM — SAMv1 §4.2
// ---------------------------------------------------------------------------

/// `cigar` words are `op_len << 4 | op`, with `MIDNSHP=X` indexing 0..=8.
#[cfg(feature = "bam")]
const CIGAR_OPS: &[u8; 9] = b"MIDNSHP=X";

/// SAM `FLAG` bits, in the order the report prints them.
#[cfg(feature = "bam")]
const SAM_FLAGS: &[(u16, &str)] = &[
    (0x1, "paired"),
    (0x2, "proper-pair"),
    (0x4, "unmapped"),
    (0x8, "mate-unmapped"),
    (0x10, "reverse"),
    (0x20, "mate-reverse"),
    (0x40, "first-in-pair"),
    (0x80, "second-in-pair"),
    (0x100, "secondary"),
    (0x200, "qc-fail"),
    (0x400, "duplicate"),
    (0x800, "supplementary"),
];

#[cfg(feature = "bam")]
fn describe_bam(data: &[u8]) -> Result<String> {
    if !GzipReader::is_gzip(data) {
        decline!("bam: not a gzip stream; BAM is BGZF");
    }
    let (raw, walk) = inflate_bgzf(data, MAX_INFLATE);
    if raw.get(..4) != Some(b"BAM\x01") {
        decline!("bam: BGZF payload does not start with the BAM magic (is this a gzipped SAM?)");
    }

    let mut out = String::new();
    let _ = writeln!(out, "bam alignment archive (BGZF-compressed)");
    write_bgzf_summary(&mut out, &walk);

    // `raw[4..]` skips the magic, and every offset below is relative to *this*
    // slice. Mixing it with an offset into `raw` shifts each record by the
    // magic's length — which a record walk still parses, just wrongly.
    let payload = raw.get(4..).unwrap_or(&[]);
    let mut cur = Cursor::new(payload);
    let Some(l_text) = cur.u32() else {
        bail!("bam: inflated stream ends before the header length");
    };
    let Some(header) = cur.take(l_text as usize) else {
        bail!("bam: header text of {l_text} bytes runs past the inflated stream");
    };
    let header_text = cstring(header);
    let _ = writeln!(out, "header: {l_text} bytes");
    write_block(&mut out, "sam header", &header_text);

    let Some(n_ref) = cur.u32() else {
        bail!("bam: inflated stream ends before the reference count");
    };
    let mut refs: Vec<(String, u32)> = Vec::new();
    let mut unlisted = 0usize;
    for _ in 0..n_ref {
        let Some(l_name) = cur.u32() else {
            bail!("bam: reference list is cut short inside a name length");
        };
        let Some(name) = cur.take(l_name as usize) else {
            bail!("bam: reference name of {l_name} bytes runs past the inflated stream");
        };
        let Some(l_ref) = cur.u32() else {
            bail!("bam: reference list is cut short before a sequence length");
        };
        if refs.len() < MAX_REFS_LISTED {
            refs.push((cstring(name), l_ref));
        } else {
            unlisted += 1;
        }
    }
    let _ = writeln!(out, "references: {n_ref}");
    for (name, len) in &refs {
        let _ = writeln!(out, "  {name}\t{len}");
    }
    if unlisted > 0 {
        let _ = writeln!(
            out,
            "  ... {unlisted} further reference(s) past the {MAX_REFS_LISTED} listed"
        );
    }

    // Alignment records (SAMv1 §4.2): after `block_size` come refID, pos,
    // l_read_name, mapq, bin, n_cigar_op, flag, l_seq, next_refID, next_pos
    // and tlen. Each record is bounded by its own `block_size`, so a
    // too-small length cannot make the walk read into its successor and a
    // too-large one ends the walk rather than the process.
    let mut records = 0u64;
    let mut flags = [0u32; SAM_FLAGS.len()];
    let mut tally: Vec<(i32, u32)> = Vec::new();
    let mut detail: Vec<String> = Vec::new();
    let mut stopped: Option<String> = None;

    while cur.remaining() >= 4 {
        let start = cur.at;
        let Some(block_size) = cur.u32() else { break };
        let body_start = cur.at;
        let Some(rec_end) = start
            .checked_add(4)
            .and_then(|s| s.checked_add(block_size as usize))
        else {
            stopped = Some(format!(
                "record {} declares a block size that overflows",
                records + 1
            ));
            break;
        };
        let Some(body) = payload.get(body_start..rec_end) else {
            stopped = Some(format!(
                "record {} runs past the inflated stream",
                records + 1
            ));
            break;
        };
        if block_size < 32 {
            stopped = Some(format!(
                "record {} declares {block_size} byte(s), under the 32-byte fixed part",
                records + 1
            ));
            break;
        }
        cur.at = rec_end;

        let mut r = Cursor::new(body);
        // Read one field per statement, in the order the record lays them
        // out. A tuple of cursor calls would read the same fields, but
        // Rust does not promise to evaluate tuple operands left to right —
        // and every one of these advances the cursor, so "same fields" is
        // not "same bytes".
        macro_rules! next {
            ($method:ident) => {
                match r.$method() {
                    Some(v) => v,
                    None => {
                        stopped = Some(format!(
                            "record {} is cut short in its fixed part",
                            records + 1
                        ));
                        break;
                    }
                }
            };
        }
        let ref_id = next!(i32);
        let pos = next!(i32);
        let l_read_name = next!(u8);
        let mapq = next!(u8);
        let _bin = next!(u16);
        let n_cigar = next!(u16);
        let flag = next!(u16);
        let l_seq = next!(u32);
        // next_refID, next_pos and tlen close the 32-byte fixed part. They
        // are stepped over rather than read: the mate's placement says
        // nothing a record line here would not already say, and skipping
        // them wrong would misplace the read name and CIGAR behind them.
        if r.skip(12).is_none() {
            stopped = Some(format!(
                "record {} is cut short in its fixed part",
                records + 1
            ));
            break;
        }
        if (n_cigar as usize).saturating_mul(4) > (block_size as usize).saturating_sub(32) {
            stopped = Some(format!(
                "record {} declares {n_cigar} CIGAR operation(s) that do not fit its block",
                records + 1
            ));
            break;
        }
        let Some(qname) = r.take(l_read_name as usize) else {
            stopped = Some(format!(
                "record {} is cut short in its read name",
                records + 1
            ));
            break;
        };
        let cigar_len = (n_cigar as usize).saturating_mul(4);
        let Some(cigar_bytes) = r.take(cigar_len) else {
            stopped = Some(format!("record {} is cut short in its CIGAR", records + 1));
            break;
        };
        let seq_len = (l_seq as usize).div_ceil(2);
        if r.take(seq_len).is_none() {
            stopped = Some(format!(
                "record {} is cut short in its sequence",
                records + 1
            ));
            break;
        }
        if r.take(l_seq as usize).is_none() {
            stopped = Some(format!(
                "record {} is cut short in its qualities",
                records + 1
            ));
            break;
        }

        records += 1;
        for (i, (bit, _)) in SAM_FLAGS.iter().enumerate() {
            if flag & bit != 0 {
                flags[i] += 1;
            }
        }
        if ref_id >= 0 && records <= MAX_TALLY_RECORDS {
            if let Some((_, n)) = tally.iter_mut().find(|(id, _)| *id == ref_id) {
                *n += 1;
            } else if tally.len() < MAX_TALLY_REFS {
                tally.push((ref_id, 1));
            }
        }
        if detail.len() < MAX_RECORDS_REPORTED {
            detail.push(describe_bam_record(
                &cstring(qname),
                ref_id,
                pos,
                mapq,
                cigar_bytes,
                flag,
                &refs,
            ));
        }
    }

    let _ = writeln!(
        out,
        "alignment records: {records} (within the inflated prefix)"
    );
    let breakdown: Vec<String> = SAM_FLAGS
        .iter()
        .zip(flags.iter())
        .filter(|(_, n)| **n > 0)
        .map(|((_, name), n)| format!("{name} {n}"))
        .collect();
    let _ = writeln!(
        out,
        "  flags: {}",
        if breakdown.is_empty() {
            "none set".to_string()
        } else {
            breakdown.join(", ")
        }
    );

    if !tally.is_empty() {
        let mut sorted = tally;
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let shown = sorted.len().min(MAX_TALLY_SHOWN);
        let _ = writeln!(
            out,
            "reads per reference (over the first {} record(s)):",
            records.min(MAX_TALLY_RECORDS)
        );
        for (ref_id, n) in sorted.iter().take(shown) {
            let _ = writeln!(out, "  {}\t{n}", ref_name(*ref_id, &refs));
        }
        if sorted.len() > shown {
            let _ = writeln!(out, "  ... {} more reference(s)", sorted.len() - shown);
        }
    }

    if !detail.is_empty() {
        let _ = writeln!(out, "records (first {} of {records}):", detail.len());
        for line in &detail {
            let _ = writeln!(out, "  {line}");
        }
    }
    if let Some(note) = stopped {
        let _ = writeln!(out, "note: record walk stopped: {note}");
    }
    let _ = writeln!(
        out,
        "not decoded: base sequences, base qualities, auxiliary tags (NM/MD/SA/RG/...)"
    );
    Ok(out)
}

#[cfg(feature = "bam")]
fn ref_name(ref_id: i32, refs: &[(String, u32)]) -> String {
    if ref_id < 0 {
        return "unmapped".to_string();
    }
    match refs.get(ref_id as usize) {
        Some((name, _)) => name.clone(),
        None => format!("ref#{ref_id} (past the {MAX_REFS_LISTED} listed)"),
    }
}

#[cfg(feature = "bam")]
fn describe_bam_record(
    qname: &str,
    ref_id: i32,
    pos: i32,
    mapq: u8,
    cigar_bytes: &[u8],
    flag: u16,
    refs: &[(String, u32)],
) -> String {
    let mut cigar = String::new();
    for word in cigar_bytes.as_chunks::<4>().0 {
        let v = u32::from_le_bytes(*word);
        let op = CIGAR_OPS.get((v & 0x0f) as usize).copied().unwrap_or(b'?');
        let _ = write!(cigar, "{}{}", v >> 4, op as char);
    }
    if cigar.is_empty() {
        cigar.push('*');
    }
    let tags: Vec<&str> = SAM_FLAGS
        .iter()
        .filter(|(bit, _)| flag & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    // An unmapped read stores pos = -1, which SAM prints as POS 0; saying
    // "unmapped:0" reads like a coordinate on a reference it is not on.
    let site = if ref_id < 0 {
        "unmapped".to_string()
    } else {
        format!("{}:{}", ref_name(ref_id, refs), pos + 1)
    };
    format!("{qname}\t{site}\tmapq {mapq}\t{cigar}\t{}", tags.join(","))
}

// ---------------------------------------------------------------------------
// BCF — BCFv1_qref (obsolete) and BCFv2_qref (the one in use).
//
// BCF2's magic is `BCF\x02` plus a minor-version byte; htslib writes
// `BCF\2\2` and rejects anything else. BCF1's magic is the four bytes
// `BCF\x04` and its header is a different arrangement entirely, so the two
// are told apart by the third byte and neither is guessed at.
// ---------------------------------------------------------------------------

#[cfg(feature = "bcf")]
fn describe_bcf(data: &[u8]) -> Result<String> {
    if !GzipReader::is_gzip(data) {
        decline!("bcf: not a gzip stream; BCF is BGZF");
    }
    let (raw, walk) = inflate_bgzf(data, MAX_INFLATE);
    let Some(kind) = raw.get(3).copied() else {
        decline!("bcf: inflated stream is too short to hold a magic");
    };
    if raw.get(..3) != Some(b"BCF") {
        decline!("bcf: BGZF payload does not start with a BCF magic (is this a gzipped VCF?)");
    }
    let mut out = String::new();
    write_bgzf_summary(&mut out, &walk);
    match kind {
        0x02 => describe_bcf2(&raw, &mut out)?,
        0x04 => describe_bcf1(&raw, &mut out)?,
        other => bail!(
            "bcf: magic BCF\\x{other:02x} is neither BCF2 (BCF\\x02 + version) nor BCF1 (BCF\\x04)"
        ),
    }
    Ok(out)
}

/// BCF2: magic(4) + `l_text` + the VCF header text, then records framed as
/// `l_shared` bytes of shared fields followed by `l_indiv` bytes of
/// per-sample fields. Only the framing is walked: the fields inside are
/// typed blobs whose keys are dictionary indices from the header.
#[cfg(feature = "bcf")]
fn describe_bcf2(raw: &[u8], out: &mut String) -> Result<()> {
    let version = raw.get(4).copied().unwrap_or(0);
    let _ = writeln!(out, "bcf {version}.2 variant calls (BGZF-compressed)");

    let mut cur = Cursor::new(raw.get(5..).unwrap_or(&[]));
    let Some(l_text) = cur.i32() else {
        bail!("bcf: inflated stream ends before the header length");
    };
    if l_text < 0 {
        bail!("bcf: header length {l_text} is negative");
    }
    let Some(text) = cur.take(l_text as usize) else {
        bail!("bcf: header text of {l_text} bytes runs past the inflated stream");
    };
    // The terminating NUL is inside `l_text` but is not part of the text.
    let header_text = cstring(text);
    let _ = writeln!(
        out,
        "header: {l_text} bytes (VCF text; carries the contig and ID dictionaries)"
    );
    write_block(out, "vcf header", &header_text);

    for line in header_text.lines() {
        if line.starts_with("#CHROM") {
            // Nine fixed columns (CHROM POS ID REF ALT QUAL FILTER INFO
            // FORMAT), then one per sample.
            let columns = line.split('\t').filter(|f| !f.is_empty()).count();
            let _ = writeln!(out, "sample columns: {}", columns.saturating_sub(9));
            break;
        }
    }

    let mut records = 0u64;
    let mut stopped: Option<String> = None;
    while cur.remaining() >= 8 {
        let Some(l_shared) = cur.i32() else { break };
        if l_shared < 0 || cur.take(l_shared as usize).is_none() {
            stopped = Some(format!("record {} is cut short", records + 1));
            break;
        }
        let Some(l_indiv) = cur.i32() else {
            stopped = Some(format!("record {} is cut short", records + 1));
            break;
        };
        if l_indiv < 0 || cur.take(l_indiv as usize).is_none() {
            stopped = Some(format!("record {} is cut short", records + 1));
            break;
        }
        records += 1;
    }
    let _ = writeln!(
        out,
        "variant records: {records} (within the inflated prefix)"
    );
    if let Some(note) = stopped {
        let _ = writeln!(out, "note: record walk stopped: {note}");
    }
    let _ = writeln!(
        out,
        "not decoded: per-record alleles, INFO keys and genotypes (typed blobs keyed by the header dictionary)"
    );
    Ok(())
}

/// BCF1: magic(4) + `l_seqnm` + the NUL-separated sequence dictionary +
/// `l_smpl` + the sample count + `l_meta` + the VCF meta-data lines.
#[cfg(feature = "bcf")]
fn describe_bcf1(raw: &[u8], out: &mut String) -> Result<()> {
    let _ = writeln!(
        out,
        "bcf 1 variant calls (BGZF-compressed; obsolete layout, superseded by BCF2)"
    );
    let mut cur = Cursor::new(raw.get(4..).unwrap_or(&[]));

    let Some(l_seqnm) = cur.i32() else {
        bail!("bcf: inflated stream ends before the sequence dictionary length");
    };
    if l_seqnm < 0 {
        bail!("bcf: sequence dictionary length {l_seqnm} is negative");
    }
    let Some(seqnm) = cur.take(l_seqnm as usize) else {
        bail!("bcf: sequence dictionary of {l_seqnm} bytes runs past the inflated stream");
    };
    let names = nul_list(seqnm);
    let _ = writeln!(out, "sequence dictionary: {} name(s)", names.len());
    for name in names.iter().take(MAX_TALLY_SHOWN) {
        let _ = writeln!(out, "  {name}");
    }
    if names.len() > MAX_TALLY_SHOWN {
        let _ = writeln!(out, "  ... {} more", names.len() - MAX_TALLY_SHOWN);
    }

    let Some(l_smpl) = cur.i32() else {
        bail!("bcf: inflated stream ends before the sample count");
    };
    let _ = writeln!(out, "samples: {}", l_smpl.max(0));

    let Some(l_meta) = cur.i32() else {
        bail!("bcf: inflated stream ends before the meta-data length");
    };
    if l_meta < 0 {
        bail!("bcf: meta-data length {l_meta} is negative");
    }
    let Some(meta) = cur.take(l_meta as usize) else {
        bail!("bcf: meta-data of {l_meta} bytes runs past the inflated stream");
    };
    write_block(
        out,
        "header",
        &String::from_utf8_lossy(meta).replace('\0', "\n"),
    );

    let mut records = 0u64;
    while cur.remaining() >= 8 {
        let Some(l_shared) = cur.i32() else { break };
        if l_shared < 0 || cur.take(l_shared as usize).is_none() {
            break;
        }
        let Some(l_indiv) = cur.i32() else { break };
        if l_indiv < 0 || cur.take(l_indiv as usize).is_none() {
            break;
        }
        records += 1;
    }
    let _ = writeln!(
        out,
        "variant records: {records} (within the inflated prefix)"
    );
    let _ = writeln!(
        out,
        "not decoded: per-record alleles, INFO keys and genotypes"
    );
    Ok(())
}

/// NUL-separated names, which is how BCF1 carries its dictionaries. A
/// trailing NUL terminates the list; it is not an empty final name.
#[cfg(feature = "bcf")]
fn nul_list(raw: &[u8]) -> Vec<String> {
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(cstring)
        .collect()
}

// ---------------------------------------------------------------------------
// CRAM — CRAMv3 §7 (container header), §8 (blocks); CRAMv2.1 §6/§7.
//
// The container header is walked in htslib's field order, the one that
// reads real files: the explicit `num_landmarks` count sits between the
// block count and the landmarks themselves, and the CRC32 tail exists from
// CRAM 3 on.
//
// Three things about the layout are load-bearing, and each of them is
// where the obvious reading is wrong:
//
//  * `length` is the size of the container's *blocks* — the block headers,
//    their data and their checksums — and not the size of the container.
//    The container header carries its own size, so the next container is
//    `header size + length` bytes further on. A reader that steps
//    `length` bytes from the container's start lands inside the header's
//    own blocks, and every container after the first is then read wrong.
//  * A block occupies its header, its data and — from CRAM 3 on — its
//    CRC32. A reader that steps over the data alone lands inside the
//    *next* block's header, and every block after the first is then read
//    wrong.
//  * The specification's `array<itf8> landmarks` row does not name the
//    count that precedes the landmarks, and htslib writes and reads it.
//
// The block count is the reader's only guide *inside* the blocks region,
// and a producer may disagree with it: htsjdk writes a CRAM 3.1 file
// whose second container declares 28 blocks and carries 30. So the region
// is bounded by `length`, and a block that will not parse ends the block
// list rather than the walk.
// ---------------------------------------------------------------------------

#[cfg(feature = "cram")]
const CRAM_METHODS: &[(u8, &str)] = &[
    (0, "raw"),
    (1, "gzip"),
    (2, "bzip2"),
    (3, "lzma"),
    (4, "rans4x8"),
    (5, "rans4x16"),
    (6, "adaptive-arithmetic"),
    (7, "fqzcomp"),
    (8, "name-tokeniser"),
];

#[cfg(feature = "cram")]
const CRAM_CONTENT_TYPES: &[(u8, &str)] = &[
    (0, "file header"),
    (1, "compression header"),
    (2, "slice header"),
    (4, "external data"),
    (5, "core data"),
];

/// The layout of one CRAM edition.
///
/// The editions differ in two places, and both are settled by htslib's
/// `cram_read_container` and `cram_read_block` and by the specifications:
/// CRAM 2's record counter is an ITF-8 where CRAM 3's is an LTF-8, and
/// CRAM 3 added the CRC32 that follows the container header and the one
/// that follows every block.
#[derive(Clone, Copy)]
#[cfg(feature = "cram")]
struct CramEdition {
    /// Whether the record counter is an LTF-8 (CRAM 3) rather than an ITF-8.
    counter_ltf8: bool,
    /// Whether a CRC32 follows the container header and every block.
    crc32: bool,
}

/// The editions this reader reads.
///
/// CRAM 2 and CRAM 3 are read. CRAM 1 and CRAM 4 are refused by name, and
/// the refusal says why: see `cram_edition_refusal`.
#[cfg(feature = "cram")]
fn cram_edition(major: u8) -> Option<CramEdition> {
    match major {
        2 => Some(CramEdition {
            counter_ltf8: false,
            crc32: false,
        }),
        3 => Some(CramEdition {
            counter_ltf8: true,
            crc32: true,
        }),
        _ => None,
    }
}

/// Why an edition is refused, by name.
#[cfg(feature = "cram")]
fn cram_edition_refusal(major: u8) -> &'static str {
    match major {
        1 => {
            "no CRAM 1 specification is published (the CRAM 2.1 specification says of \
             1.0 that 2.0 \"tidied up implementation vs specification differences in \
             1.0\", so the two implementations of it disagreed with each other), and \
             htsjdk's container reader cannot read a CRAM 1 container at all: it \
             reads the container's length as an int32 for every edition, where CRAM 1 \
             wrote an ITF-8. There is nothing here to check a reading against"
        }
        4 => {
            "CRAM 4 is a draft edition with its own signed variable-length integers, \
             and no CRAM 4 file was available to check a reading against"
        }
        _ => "it is not an edition this reader knows",
    }
}

/// One CRAM block.
#[cfg(feature = "cram")]
struct CramBlock {
    method: u8,
    content_type: u8,
    content_id: i32,
    raw_size: i32,
    data_at: usize,
    data_len: usize,
    /// The bytes the block occupies: its header, its data and — from CRAM
    /// 3 on — its CRC32.
    total_len: usize,
    /// The CRC32 CRAM 3 writes after the block, and what the block's own
    /// bytes hash to. `None` when the edition writes none, or when the
    /// block is truncated and there is nothing to hash.
    crc32: Option<CramCrc>,
}

/// A CRC32 a CRAM 3 container header or block carries, and what the bytes
/// it covers actually hash to.
///
/// CRAM 3 writes the CRC32 of the container header after the header, and
/// the CRC32 of the block (its header and its data as stored) after every
/// block. The checksum is the IEEE 802.3 CRC-32 that gzip and ZIP carry,
/// stored little-endian — the same `crc32()` htslib calls.
#[cfg(feature = "cram")]
struct CramCrc {
    /// The value the file carries.
    stored: u32,
    /// The value the covered bytes hash to.
    computed: u32,
}

#[cfg(feature = "cram")]
impl CramCrc {
    fn ok(&self) -> bool {
        self.stored == self.computed
    }
}

/// One CRAM container header.
#[cfg(feature = "cram")]
struct CramContainer {
    /// The size of the header itself. The container's `length` counts the
    /// blocks alone, so the next container is this many bytes plus
    /// `length` further on.
    header_len: usize,
    /// The size of the container's blocks region.
    length: i32,
    ref_id: i32,
    start: i32,
    span: i32,
    n_records: i32,
    record_counter: i64,
    bases: i64,
    n_blocks: i32,
    /// The CRC32 CRAM 3 writes after the header, and what the header's own
    /// bytes hash to. `None` when the edition writes none.
    crc32: Option<CramCrc>,
}

#[cfg(feature = "cram")]
fn cram_method_name(m: u8) -> String {
    CRAM_METHODS
        .iter()
        .find(|(code, _)| *code == m)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("unknown-{m}"))
}

#[cfg(feature = "cram")]
fn cram_content_name(t: u8) -> String {
    CRAM_CONTENT_TYPES
        .iter()
        .find(|(code, _)| *code == t)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("reserved-{t}"))
}

/// Read one container header.
///
/// `at` is where the header starts, and the returned `header_len` is its
/// size in bytes: the caller adds it to the container's `length` to find
/// the next container.
#[cfg(feature = "cram")]
fn read_container_header(raw: &[u8], at: usize, edition: &CramEdition) -> Option<CramContainer> {
    let mut c = Cursor::new(raw.get(at..)?);
    let length = c.i32()?;
    if length < 0 {
        return None;
    }
    let ref_id = c.itf8()?;
    let start = c.itf8()?;
    let span = c.itf8()?;
    let n_records = c.itf8()?;
    // The record counter is an ITF-8 in CRAM 2 and an LTF-8 in CRAM 3.
    let record_counter = if edition.counter_ltf8 {
        c.ltf8()? as i64
    } else {
        i64::from(c.itf8()?)
    };
    let bases = c.ltf8()? as i64;
    let n_blocks = c.itf8()?;
    if !(0..=MAX_CRAMS_BLOCKS as i32).contains(&n_blocks) {
        return None;
    }
    // The spec's `array<itf8> landmarks` row does not name this count, but
    // htslib writes and reads it, and without it the landmark bytes
    // cannot be told from the CRC32 that follows them.
    let n_landmarks = c.itf8()?;
    if !(0..=MAX_CRAMS_LANDMARKS as i32).contains(&n_landmarks) {
        return None;
    }
    for _ in 0..n_landmarks {
        c.itf8()?;
    }
    // From CRAM 3 on the header carries a CRC32 of the header's own bytes.
    // The header is everything from the container's first byte up to the
    // CRC32, so that is what is hashed.
    let crc = if edition.crc32 {
        let covered = c.at;
        let stored = c.i32()? as u32;
        Some(CramCrc {
            stored,
            computed: crc32(raw.get(at..at.checked_add(covered)?)?),
        })
    } else {
        None
    };

    Some(CramContainer {
        header_len: c.at,
        length,
        ref_id,
        start,
        span,
        n_records,
        record_counter,
        bases,
        n_blocks,
        crc32: crc,
    })
}

/// The end-of-file marker container: an empty container whose start
/// position is the ASCII "EOF" (htslib's `cram_read_container`).
#[cfg(feature = "cram")]
fn cram_is_eof(c: &CramContainer) -> bool {
    c.n_records == 0 && c.ref_id == -1 && c.start == 0x454f46
}

/// The CRAM 2.1 end-of-file marker: the specification's own 30 bytes, §8.
///
/// The reference id is the five `ff`s the listing spells. htsjdk writes the
/// `ff ff ff ff 0f` spelling instead, which decodes to the same -1 — the
/// last byte of an ITF-8's 5-byte form is masked with `0x0f` — so both are
/// read and neither is ruled out.
#[cfg(feature = "cram")]
const CRAM_2_1_EOF_MARKER: [u8; 30] = [
    0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe0, 0x45, 0x4f, 0x46, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x06, 0x06, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
];

/// The CRAM 3.1 end-of-file marker: the specification's own 38 bytes, §9.
///
/// The same container as CRAM 2.1's, with the two CRC32s CRAM 3 added — one
/// after the container header and one after the block.
#[cfg(feature = "cram")]
const CRAM_3_1_EOF_MARKER: [u8; 38] = [
    0x0f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x0f, 0xe0, 0x45, 0x4f, 0x46, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x05, 0xbd, 0xd9, 0x4f, 0x00, 0x01, 0x00, 0x06, 0x06, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0xee, 0x63, 0x01, 0x4b,
];

/// How the end-of-file marker spells the reference id -1.
///
/// Both spellings decode to -1, so the reader says which one a file carries
/// instead of ruling either out.
#[cfg(feature = "cram")]
fn cram_eof_ref_id_spelling(bytes: &[u8]) -> &'static str {
    match bytes.get(4..9) {
        Some([0xff, 0xff, 0xff, 0xff, 0xff]) => "ff ff ff ff ff",
        Some([0xff, 0xff, 0xff, 0xff, 0x0f]) => "ff ff ff ff 0f",
        _ => "an unrecognized spelling",
    }
}

/// What the end-of-file marker is, for the report.
///
/// The marker is a literal byte string in both editions, so the reader can
/// say whether the file carries the specification's own bytes.
#[cfg(feature = "cram")]
fn cram_eof_marker_note(raw: &[u8], at: usize, c: &CramContainer) -> String {
    let total = c.header_len.saturating_add(c.length.max(0) as usize);
    let mut note = format!("{total} byte(s)");
    let Some(bytes) = raw.get(at..at.saturating_add(total)) else {
        note.push_str(", truncated");
        return note;
    };
    let _ = write!(
        note,
        ", the reference id -1 spelled {}",
        cram_eof_ref_id_spelling(bytes)
    );
    if bytes == CRAM_2_1_EOF_MARKER {
        note.push_str("; the CRAM 2.1 specification's own byte string, §8");
    } else if bytes == CRAM_3_1_EOF_MARKER {
        note.push_str("; the CRAM 3.1 specification's own byte string, §9");
    }
    note
}

// ---------------------------------------------------------------------------
// CRAM 2.1's record encodings: the compression header block's three maps,
// the slice header block, the codecs, and the records themselves.
// ---------------------------------------------------------------------------

/// The preservation map of a CRAM compression header block (CRAMv2.1 §7.4).
///
/// The map says what the file kept: whether the read names are there,
/// whether the alignment positions are delta encoded, whether a reference
/// is needed to restore the data, the substitution matrix and the tag
/// dictionary.
#[cfg(feature = "cram")]
#[derive(Default)]
struct CramPreservation {
    read_names: bool,
    ap_delta: bool,
    reference_required: bool,
    substitution_matrix: [u8; 5],
    tag_dictionary: Vec<u8>,
}

/// One codec and its parameters (CRAMv2.1 §3 and §12.2).
///
/// The codec id is the first integer of an encoding and the second is the
/// number of bytes the codec-specific values take; this is what the values
/// below were read from.
#[cfg(feature = "cram")]
enum CramCodec {
    /// Codec 0: the data series is not preserved.
    Null,
    /// Codec 1: the bytes live in an external block.
    External { block_id: i32 },
    /// Codec 2: Golomb coding.
    Golomb { offset: i32, m: i32 },
    /// Codec 3: canonical Huffman coding.
    Huffman {
        alphabet: Vec<i32>,
        lengths: Vec<i32>,
    },
    /// Codec 4: a byte array whose length is itself encoded.
    ByteArrayLen {
        lengths: Box<CramCodec>,
        values: Box<CramCodec>,
    },
    /// Codec 5: a byte array terminated by a stop byte.
    ByteArrayStop { stop: u8, block_id: i32 },
    /// Codec 6: beta coding.
    Beta { offset: i32, bits: i32 },
    /// Codec 7: subexponential coding.
    Subexp { offset: i32, k: i32 },
    /// Codec 8: Golomb-Rice coding.
    GolombRice { offset: i32, log2m: i32 },
    /// Codec 9: Elias gamma coding.
    Gamma { offset: i32 },
}

/// The compression header block of a slice (CRAMv2.1 §7.4).
#[cfg(feature = "cram")]
struct CramCompressionHeader {
    preservation: CramPreservation,
    /// The data series encodings, by their two-letter name.
    encodings: Vec<([u8; 2], CramCodec)>,
    /// The tag value encodings, by the tag's three-byte key.
    tag_encodings: Vec<(i32, CramCodec)>,
}

#[cfg(feature = "cram")]
impl CramCompressionHeader {
    /// The encoding of one data series, if the file has one.
    fn encoding(&self, name: &[u8; 2]) -> Option<&CramCodec> {
        self.encodings
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, codec)| codec)
    }

    /// The encoding of one tag's value, if the file has one.
    fn tag_encoding(&self, key: i32) -> Option<&CramCodec> {
        self.tag_encodings
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, codec)| codec)
    }
}

/// The slice header block of a slice (CRAMv2.1 §7.5).
#[cfg(feature = "cram")]
struct CramSliceHeader {
    reference_id: i32,
    alignment_start: i32,
    alignment_span: i32,
    records: i32,
    record_counter: i64,
    blocks: i32,
    content_ids: Vec<i32>,
    embedded_reference: i32,
    reference_md5: [u8; 16],
}

/// Read one map: the size in bytes, the number of keys, then the entries.
///
/// The size counts the key count and the entries together, so it is what
/// says where the next map starts (CRAMv2.1 §2.3).
#[cfg(feature = "cram")]
fn cram_read_map<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let mut c = Cursor::new(bytes.get(*at..)?);
    let size = c.itf8()?;
    if size < 0 {
        return None;
    }
    let start = at.checked_add(c.at)?;
    let body = bytes.get(start..start.checked_add(size as usize)?)?;
    *at = start.checked_add(size as usize)?;
    Some(body)
}

/// Read the preservation map's entries (CRAMv2.1 §7.4).
#[cfg(feature = "cram")]
fn cram_read_preservation(body: &[u8]) -> Option<CramPreservation> {
    let mut c = Cursor::new(body);
    let n = c.itf8()?;
    let mut p = CramPreservation::default();
    for _ in 0..n.max(0) {
        let key = c.take(2)?;
        match key {
            b"RN" => p.read_names = c.u8()? != 0,
            b"AP" => p.ap_delta = c.u8()? != 0,
            b"RR" => p.reference_required = c.u8()? != 0,
            b"SM" => p.substitution_matrix = c.take(5)?.try_into().ok()?,
            b"TD" => {
                let len = c.itf8()?;
                if len < 0 {
                    return None;
                }
                p.tag_dictionary = c.take(len as usize)?.to_vec();
            }
            // A key this reader does not know carries a value whose type it
            // cannot guess, so the map stops here rather than misread.
            _ => break,
        }
    }
    Some(p)
}

/// Read one codec and its parameters (CRAMv2.1 §3 and §12.2).
#[cfg(feature = "cram")]
fn cram_read_codec(c: &mut Cursor) -> Option<CramCodec> {
    let id = c.itf8()?;
    let n = c.itf8()?;
    if n < 0 {
        return None;
    }
    let mut p = Cursor::new(c.take(n as usize)?);
    Some(match id {
        0 => CramCodec::Null,
        1 => CramCodec::External {
            block_id: p.itf8()?,
        },
        2 => CramCodec::Golomb {
            offset: p.itf8()?,
            m: p.itf8()?,
        },
        3 => {
            // The alphabet and the bit lengths are each a counted array.
            let mut alphabet = Vec::new();
            let count = p.itf8()?;
            for _ in 0..count.max(0) {
                alphabet.push(p.itf8()?);
            }
            let mut lengths = Vec::new();
            let count = p.itf8()?;
            for _ in 0..count.max(0) {
                lengths.push(p.itf8()?);
            }
            CramCodec::Huffman { alphabet, lengths }
        }
        4 => {
            let lengths = cram_read_codec(&mut p)?;
            let values = cram_read_codec(&mut p)?;
            CramCodec::ByteArrayLen {
                lengths: Box::new(lengths),
                values: Box::new(values),
            }
        }
        5 => CramCodec::ByteArrayStop {
            stop: p.u8()?,
            block_id: p.itf8()?,
        },
        6 => CramCodec::Beta {
            offset: p.itf8()?,
            bits: p.itf8()?,
        },
        7 => CramCodec::Subexp {
            offset: p.itf8()?,
            k: p.itf8()?,
        },
        8 => CramCodec::GolombRice {
            offset: p.itf8()?,
            log2m: p.itf8()?,
        },
        9 => CramCodec::Gamma { offset: p.itf8()? },
        _ => return None,
    })
}

/// Read the data series encoding map's entries (CRAMv2.1 §7.4).
#[cfg(feature = "cram")]
fn cram_read_encodings(body: &[u8]) -> Option<Vec<([u8; 2], CramCodec)>> {
    let mut c = Cursor::new(body);
    let n = c.itf8()?;
    let mut out = Vec::new();
    for _ in 0..n.max(0) {
        let key: [u8; 2] = c.take(2)?.try_into().ok()?;
        let codec = cram_read_codec(&mut c)?;
        out.push((key, codec));
    }
    Some(out)
}

/// Read the tag encoding map's entries (CRAMv2.1 §7.4).
///
/// A tag's key is the three bytes of its name and type read as a big
/// endian integer, written as an ITF-8.
#[cfg(feature = "cram")]
fn cram_read_tag_encodings(body: &[u8]) -> Option<Vec<(i32, CramCodec)>> {
    let mut c = Cursor::new(body);
    let n = c.itf8()?;
    let mut out = Vec::new();
    for _ in 0..n.max(0) {
        let key = c.itf8()?;
        let codec = cram_read_codec(&mut c)?;
        out.push((key, codec));
    }
    Some(out)
}

/// Read a compression header block's three maps.
///
/// The preservation map comes first, then the data series encoding map,
/// then the tag encoding map; each map's size says where the next one
/// starts (CRAMv2.1 §7.4).
#[cfg(feature = "cram")]
fn cram_read_compression_header(bytes: &[u8]) -> Option<CramCompressionHeader> {
    let mut at = 0usize;
    let preservation = cram_read_preservation(cram_read_map(bytes, &mut at)?)?;
    let encodings = cram_read_encodings(cram_read_map(bytes, &mut at)?)?;
    let tag_encodings = cram_read_tag_encodings(cram_read_map(bytes, &mut at)?)?;
    Some(CramCompressionHeader {
        preservation,
        encodings,
        tag_encodings,
    })
}

/// Read a slice header block (CRAMv2.1 §7.5).
#[cfg(feature = "cram")]
fn cram_read_slice_header(bytes: &[u8]) -> Option<CramSliceHeader> {
    let mut c = Cursor::new(bytes);
    let reference_id = c.itf8()?;
    let alignment_start = c.itf8()?;
    let alignment_span = c.itf8()?;
    let records = c.itf8()?;
    let record_counter = c.ltf8()? as i64;
    let blocks = c.itf8()?;
    let count = c.itf8()?;
    let mut content_ids = Vec::new();
    for _ in 0..count.max(0) {
        content_ids.push(c.itf8()?);
    }
    let embedded_reference = c.itf8()?;
    let reference_md5: [u8; 16] = c.take(16)?.try_into().ok()?;
    Some(CramSliceHeader {
        reference_id,
        alignment_start,
        alignment_span,
        records,
        record_counter,
        blocks,
        content_ids,
        embedded_reference,
        reference_md5,
    })
}

/// The core data block's bit stream (CRAMv2.1 §2.2 and §7.6).
///
/// The bits are most significant bit first, and the last byte of a stream
/// that does not end on a byte boundary is shifted to the left.
#[cfg(feature = "cram")]
struct CramBits<'a> {
    b: &'a [u8],
    byte: usize,
    bit: u32,
}

#[cfg(feature = "cram")]
impl<'a> CramBits<'a> {
    fn new(b: &'a [u8]) -> Self {
        CramBits { b, byte: 0, bit: 0 }
    }

    /// Read one bit.
    fn bit(&mut self) -> Option<u32> {
        let byte = *self.b.get(self.byte)?;
        let v = (byte >> (7 - self.bit)) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.byte = self.byte.checked_add(1)?;
        }
        Some(u32::from(v))
    }

    /// Read `n` bits, most significant first, as an unsigned integer.
    fn read(&mut self, n: u32) -> Option<u32> {
        if n > 32 {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }
}

/// The state a slice's data series are read against: the core data
/// block's bit stream and the external blocks the encodings name.
#[cfg(feature = "cram")]
struct CramDecode<'a> {
    bits: CramBits<'a>,
    /// The external blocks: their content id, their bytes, and how far
    /// into each the reader is.
    externals: Vec<(i32, Vec<u8>, usize)>,
}

#[cfg(feature = "cram")]
impl CramDecode<'_> {
    /// Read one integer from a data series.
    fn read_int(&mut self, codec: &CramCodec) -> Option<i64> {
        match codec {
            CramCodec::Null => None,
            CramCodec::External { block_id } => {
                let (_, bytes, at) = self
                    .externals
                    .iter_mut()
                    .find(|(id, _, _)| id == block_id)?;
                let mut c = Cursor::new(bytes.get(*at..)?);
                let v = c.itf8()?;
                *at += c.at;
                Some(i64::from(v))
            }
            CramCodec::Beta { offset, bits } => {
                if *bits < 0 || *bits > 32 {
                    return None;
                }
                let raw = i64::from(self.bits.read(*bits as u32)?);
                Some(raw - i64::from(*offset))
            }
            CramCodec::Gamma { offset } => {
                // Elias gamma: the number of leading zeroes says how many
                // bits of the value follow the separator.
                let mut zeros = 0u32;
                while self.bits.bit()? == 0 {
                    zeros += 1;
                    if zeros > 32 {
                        return None;
                    }
                }
                let low = if zeros == 0 {
                    0
                } else {
                    self.bits.read(zeros)?
                };
                let value = (1i64 << zeros) | i64::from(low);
                Some(value - i64::from(*offset))
            }
            CramCodec::Subexp { offset, k } => {
                let k = *k;
                if !(0..=32).contains(&k) {
                    return None;
                }
                // The prefix is the group index as a run of ones.
                let mut i = 0i32;
                while self.bits.bit()? == 1 {
                    i += 1;
                    if i > 32 {
                        return None;
                    }
                }
                let tail_bits = if i == 0 { k } else { k + i - 1 };
                if !(0..=32).contains(&tail_bits) {
                    return None;
                }
                let tail = i64::from(self.bits.read(tail_bits as u32)?);
                let value = if i == 0 {
                    tail
                } else {
                    tail + (1i64 << (i + k - 1) as u32)
                };
                Some(value - i64::from(*offset))
            }
            CramCodec::GolombRice { offset, log2m } => {
                let m = *log2m;
                if !(0..=31).contains(&m) {
                    return None;
                }
                let mut ones = 0i64;
                while self.bits.bit()? == 1 {
                    ones += 1;
                    if ones > 62 {
                        return None;
                    }
                }
                let rest = if m == 0 {
                    0
                } else {
                    i64::from(self.bits.read(m as u32)?)
                };
                Some(((ones << m) + rest) - i64::from(*offset))
            }
            CramCodec::Golomb { offset, m } => {
                let m = *m;
                if m <= 0 {
                    return None;
                }
                let mut ones = 0i64;
                while self.bits.bit()? == 1 {
                    ones += 1;
                    if ones > 62 {
                        return None;
                    }
                }
                // The remainder is a truncated binary code: the shorter
                // codes come first. A power of two is the Rice code, where
                // the remainder is plain binary.
                let rest = if m & (m - 1) == 0 {
                    let log2m = 32 - (m as u32).leading_zeros() - 1;
                    i64::from(self.bits.read(log2m)?)
                } else {
                    let b = 32 - (m as u32 - 1).leading_zeros();
                    let cutoff = (1i64 << b) - i64::from(m);
                    let x = i64::from(self.bits.read(b - 1)?);
                    if x < cutoff {
                        x
                    } else {
                        let y = i64::from(self.bits.read(1)?);
                        ((x << 1) | y) - (1i64 << (b - 1)) + cutoff
                    }
                };
                Some((ones * i64::from(m) + rest) - i64::from(*offset))
            }
            CramCodec::Huffman { alphabet, lengths } => {
                let code = cram_huffman_decode(self, alphabet, lengths)?;
                Some(i64::from(code))
            }
            CramCodec::ByteArrayLen { .. } => None,
            CramCodec::ByteArrayStop { .. } => None,
        }
    }

    /// Read one byte array from a data series.
    ///
    /// `len` is the length the record's own fields say the array has; the
    /// codecs that carry their own length ignore it.
    fn read_bytes(&mut self, codec: &CramCodec, len: usize) -> Option<Vec<u8>> {
        match codec {
            CramCodec::Null => None,
            CramCodec::External { block_id } => {
                let (_, bytes, at) = self
                    .externals
                    .iter_mut()
                    .find(|(id, _, _)| id == block_id)?;
                let slice = bytes.get(*at..at.checked_add(len)?)?;
                *at += len;
                Some(slice.to_vec())
            }
            CramCodec::ByteArrayStop { stop, block_id } => {
                let (_, bytes, at) = self
                    .externals
                    .iter_mut()
                    .find(|(id, _, _)| id == block_id)?;
                let start = *at;
                let mut end = start;
                while bytes.get(end) != Some(stop) {
                    end += 1;
                    if end >= bytes.len() {
                        return None;
                    }
                }
                let slice = bytes.get(start..end)?.to_vec();
                *at = end + 1;
                Some(slice)
            }
            CramCodec::ByteArrayLen { lengths, values } => {
                let n = self.read_int(lengths)?;
                if n < 0 {
                    return None;
                }
                self.read_bytes(values, n as usize)
            }
            _ => None,
        }
    }
}

/// Decode one value with a canonical Huffman code.
///
/// The alphabet is sorted by bit length and then by value, and each symbol
/// takes the next code of its length; an alphabet with a single value has
/// no output bits at all (CRAMv2.1 §12.2).
#[cfg(feature = "cram")]
fn cram_huffman_decode(decode: &mut CramDecode, alphabet: &[i32], lengths: &[i32]) -> Option<i32> {
    if alphabet.is_empty() || alphabet.len() != lengths.len() {
        return None;
    }
    let mut order: Vec<usize> = (0..alphabet.len()).collect();
    order.sort_by_key(|&i| (lengths[i], alphabet[i]));
    // The canonical codes: the first symbol takes an all-zero code of its
    // own length, and each next one takes the next code.
    let mut codes: Vec<(u32, u32, i32)> = Vec::with_capacity(order.len());
    let mut code = 0u32;
    let mut length = 0u32;
    for &i in &order {
        let l = lengths[i];
        if !(0..=32).contains(&l) {
            return None;
        }
        if length == 0 {
            length = l as u32;
            code = 0;
        } else if l as u32 > length {
            code <<= l as u32 - length;
            length = l as u32;
        }
        codes.push((code, length, alphabet[i]));
        code += 1;
    }
    if codes.len() == 1 && codes[0].1 == 0 {
        // The single-symbol case: no bits are read.
        return Some(codes[0].2);
    }
    let mut value = 0u32;
    let mut read = 0u32;
    for _ in 0..32 {
        value = (value << 1) | decode.bits.bit()?;
        read += 1;
        for &(c, l, v) in &codes {
            if l == read && c == value {
                return Some(v);
            }
        }
    }
    None
}

/// One decoded CRAM record (CRAMv2.1 §9.1).
#[cfg(feature = "cram")]
struct CramRecord {
    bam_flags: i32,
    cram_flags: i32,
    reference_id: i32,
    read_length: i32,
    alignment_start: i32,
    read_group: i32,
    read_name: Option<String>,
    mate: Option<CramMate>,
    tags: Vec<(String, Vec<u8>)>,
    features: Vec<CramFeature>,
    mapping_quality: Option<i32>,
    bases: Option<Vec<u8>>,
}

/// The mate information of a record (CRAMv2.1 §9.5).
#[cfg(feature = "cram")]
enum CramMate {
    /// The mate is stored verbatim: its flags, its reference and its
    /// position, and the size of the template.
    Detached {
        flags: i32,
        reference_id: i32,
        position: i32,
        template_size: i32,
    },
    /// The mate is further down the stream: the number of records to skip.
    Downstream(i32),
}

/// One read feature (CRAMv2.1 §9.4).
#[cfg(feature = "cram")]
struct CramFeature {
    position: i32,
    code: u8,
}

/// Read one integer from a named data series.
#[cfg(feature = "cram")]
fn cram_series_int(
    compression: &CramCompressionHeader,
    decode: &mut CramDecode,
    name: &[u8; 2],
) -> Option<i64> {
    let codec = compression.encoding(name)?;
    decode.read_int(codec)
}

/// Read one byte from a named data series.
#[cfg(feature = "cram")]
fn cram_series_byte(
    compression: &CramCompressionHeader,
    decode: &mut CramDecode,
    name: &[u8; 2],
) -> Option<u8> {
    let codec = compression.encoding(name)?;
    let value = decode.read_int(codec)?;
    u8::try_from(value).ok()
}

/// The tag ids of one tag line of the tag dictionary.
///
/// The dictionary is a list of lists of three-byte tag ids, each list
/// separated by a NUL (CRAMv2.1 §7.4).
#[cfg(feature = "cram")]
fn cram_tag_line(dictionary: &[u8], line: i32) -> Vec<i32> {
    if line < 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut index = 0i32;
    for chunk in dictionary.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        if index == line {
            for tag in chunk.as_chunks::<3>().0 {
                let key = (i32::from(tag[0]) << 16) | (i32::from(tag[1]) << 8) | i32::from(tag[2]);
                out.push(key);
            }
            return out;
        }
        index += 1;
    }
    out
}

/// The name of a tag, from its three-byte key.
#[cfg(feature = "cram")]
fn cram_tag_name(key: i32) -> String {
    let bytes = [
        ((key >> 16) & 0xff) as u8,
        ((key >> 8) & 0xff) as u8,
        (key & 0xff) as u8,
    ];
    cstring(&bytes)
}

/// Report one slice: its header, the encodings its records are written
/// with, and the records themselves.
#[cfg(feature = "cram")]
fn cram_write_slice(out: &mut String, slice: &CramSlice) {
    let header = &slice.header;
    let _ = writeln!(
        out,
        "  slice: reference id {}, alignment start {}, alignment span {}, {} record(s), record counter {}, {} block(s), embedded reference {}",
        header.reference_id,
        header.alignment_start,
        header.alignment_span,
        header.records,
        header.record_counter,
        header.blocks,
        header.embedded_reference
    );
    let p = &slice.compression.preservation;
    let mut matrix = String::new();
    for b in p.substitution_matrix {
        let _ = write!(matrix, "{b:02x}");
    }
    let mut md5 = String::new();
    for b in header.reference_md5 {
        let _ = write!(md5, "{b:02x}");
    }
    let _ = writeln!(
        out,
        "    block content ids {:?}, reference md5 {md5}",
        header.content_ids
    );
    let _ = writeln!(
        out,
        "    read names {}, alignment positions {}, reference {}, substitution matrix {matrix}, tag dictionary {} byte(s)",
        if p.read_names {
            "preserved"
        } else {
            "not preserved"
        },
        if p.ap_delta {
            "delta encoded"
        } else {
            "not delta encoded"
        },
        if p.reference_required {
            "required"
        } else {
            "not required"
        },
        p.tag_dictionary.len()
    );
    let _ = writeln!(
        out,
        "    data series encodings: {}",
        slice.compression.encodings.len()
    );
    for (key, codec) in &slice.compression.encodings {
        let _ = writeln!(out, "      {}: {}", cstring(key), cram_codec_detail(codec));
    }
    let _ = writeln!(
        out,
        "    tag encodings: {}",
        slice.compression.tag_encodings.len()
    );
    for (key, codec) in &slice.compression.tag_encodings {
        let _ = writeln!(
            out,
            "      {}: {}",
            cram_tag_name(*key),
            cram_codec_detail(codec)
        );
    }

    let mut decode = CramDecode {
        bits: CramBits::new(&slice.core),
        externals: slice
            .externals
            .iter()
            .map(|(id, bytes)| (*id, bytes.clone(), 0usize))
            .collect(),
    };
    match cram_decode_records(&slice.compression, &slice.header, &mut decode) {
        Some(records) => {
            let _ = writeln!(out, "    records: {}", records.len());
            for (i, r) in records.iter().enumerate() {
                let _ = writeln!(out, "      {i}: {}", cram_record_line(r));
            }
        }
        None => {
            let mut reason = String::new();
            if !slice.undecoded.is_empty() {
                let _ = write!(
                    reason,
                    "the external blocks {:?} use compression methods this reader does not decode:",
                    slice
                        .undecoded
                        .iter()
                        .map(|(id, _)| *id)
                        .collect::<Vec<i32>>()
                );
                for (_, method) in &slice.undecoded {
                    let _ = write!(reason, " {}", cram_method_name(*method));
                }
            } else {
                reason.push_str(
                    "the data series' encodings do not yield the values the record layout asks for",
                );
            }
            let _ = writeln!(out, "    records: not decoded ({reason})");
        }
    }
}

/// One record, on one line.
#[cfg(feature = "cram")]
fn cram_record_line(r: &CramRecord) -> String {
    let mut line = format!(
        "flags {:#x}, cram flags {:#x}, reference id {}, position {}, length {}, group {}",
        r.bam_flags, r.cram_flags, r.reference_id, r.alignment_start, r.read_length, r.read_group
    );
    if let Some(name) = &r.read_name {
        let _ = write!(line, ", name {name}");
    }
    if let Some(mate) = &r.mate {
        match mate {
            CramMate::Detached {
                flags,
                reference_id,
                position,
                template_size,
            } => {
                let _ = write!(
                    line,
                    ", mate detached (flags {flags:#x}, reference id {reference_id}, position {position}, template size {template_size})"
                );
            }
            CramMate::Downstream(n) => {
                let _ = write!(line, ", mate {n} record(s) downstream");
            }
        }
    }
    for (name, value) in &r.tags {
        let _ = write!(line, ", {name}={}", cstring(value));
    }
    if !r.features.is_empty() {
        let _ = write!(line, ", read features:");
        for f in &r.features {
            let _ = write!(line, " {}@{}", f.code as char, f.position);
        }
    }
    if let Some(mq) = r.mapping_quality {
        let _ = write!(line, ", mapping quality {mq}");
    }
    if let Some(bases) = &r.bases {
        let _ = write!(line, ", bases {}", cstring(bases));
    }
    line
}

/// Decode the records of one slice (CRAMv2.1 §9.1).
///
/// The order is the specification's: the flags, the reference and the
/// position, the read name, the mate record, the tags, and then the
/// features of a mapped read or the bases of an unmapped one.
#[cfg(feature = "cram")]
fn cram_decode_records(
    compression: &CramCompressionHeader,
    header: &CramSliceHeader,
    decode: &mut CramDecode,
) -> Option<Vec<CramRecord>> {
    let mut out = Vec::new();
    let mut last_position = header.alignment_start;
    // The record count is an ITF-8 of the slice header, and a compression
    // header whose data series are all zero-bit constants decodes a
    // record without consuming a single bit -- so the count is the only
    // bound, and a crafted one walks it billions of times. The BAM path
    // holds the same line with `MAX_TALLY_RECORDS`.
    for _ in 0..header.records.max(0).min(MAX_TALLY_RECORDS as i32) {
        out.push(cram_decode_record(
            compression,
            header,
            decode,
            &mut last_position,
        )?);
    }
    Some(out)
}

/// Decode one record (CRAMv2.1 §9.1).
#[cfg(feature = "cram")]
fn cram_decode_record(
    compression: &CramCompressionHeader,
    header: &CramSliceHeader,
    decode: &mut CramDecode,
    last_position: &mut i32,
) -> Option<CramRecord> {
    let bam_flags = cram_series_int(compression, decode, b"BF")? as i32;
    let cram_flags = cram_series_int(compression, decode, b"CF")? as i32;
    // The reference id is read only in a multi-reference slice; in any
    // other slice it is the slice's own.
    let reference_id = if header.reference_id == -2 {
        cram_series_int(compression, decode, b"RI")? as i32
    } else {
        header.reference_id
    };
    let read_length = cram_series_int(compression, decode, b"RL")? as i32;
    let mut alignment_start = cram_series_int(compression, decode, b"AP")? as i32;
    if compression.preservation.ap_delta {
        alignment_start = alignment_start.wrapping_add(*last_position);
    }
    *last_position = alignment_start;
    let read_group = cram_series_int(compression, decode, b"RG")? as i32;

    let read_name = if compression.preservation.read_names {
        let codec = compression.encoding(b"RN")?;
        Some(cstring(&decode.read_bytes(codec, 0)?))
    } else {
        None
    };

    // The mate record: verbatim when the record is detached from its
    // mate, a distance when the mate is further down the stream.
    let mate = if cram_flags & 0x2 != 0 {
        let flags = cram_series_int(compression, decode, b"MF")? as i32;
        if !compression.preservation.read_names {
            // The read name comes with the mate record.
            let codec = compression.encoding(b"RN")?;
            decode.read_bytes(codec, 0)?;
        }
        Some(CramMate::Detached {
            flags,
            reference_id: cram_series_int(compression, decode, b"NS")? as i32,
            position: cram_series_int(compression, decode, b"NP")? as i32,
            template_size: cram_series_int(compression, decode, b"TS")? as i32,
        })
    } else if cram_flags & 0x4 != 0 {
        Some(CramMate::Downstream(
            cram_series_int(compression, decode, b"NF")? as i32,
        ))
    } else {
        None
    };

    // The tags: the tag line says which line of the tag dictionary the
    // record's tags are, and each tag's value has its own encoding.
    let tag_line = cram_series_int(compression, decode, b"TL")? as i32;
    let mut tags = Vec::new();
    for key in cram_tag_line(&compression.preservation.tag_dictionary, tag_line) {
        let codec = compression.tag_encoding(key)?;
        let value = decode.read_bytes(codec, 0)?;
        tags.push((cram_tag_name(key), value));
    }

    let mut features = Vec::new();
    let mut mapping_quality = None;
    let mut bases = None;
    if bam_flags & 0x4 == 0 {
        // A mapped read: the read features, then the mapping quality.
        let count = cram_series_int(compression, decode, b"FN")?;
        if !(0..=1_000_000).contains(&count) {
            return None;
        }
        for _ in 0..count {
            let position = cram_series_int(compression, decode, b"FP")? as i32;
            let code = cram_series_byte(compression, decode, b"FC")?;
            cram_skip_feature(compression, decode, code, read_length)?;
            features.push(CramFeature { position, code });
        }
        mapping_quality = Some(cram_series_int(compression, decode, b"MQ")? as i32);
    } else if cram_flags & 0x8 == 0 {
        // An unmapped read: the bases.
        let codec = compression.encoding(b"BA")?;
        bases = Some(decode.read_bytes(codec, read_length.max(0) as usize)?);
    }
    // The quality scores, when they are stored as an array.
    if cram_flags & 0x1 != 0 {
        let codec = compression.encoding(b"QS")?;
        decode.read_bytes(codec, read_length.max(0) as usize)?;
    }

    Some(CramRecord {
        bam_flags,
        cram_flags,
        reference_id,
        read_length,
        alignment_start,
        read_group,
        read_name,
        mate,
        tags,
        features,
        mapping_quality,
        bases,
    })
}

/// Read the data a read feature carries (CRAMv2.1 §9.4).
///
/// The data is read so that the bit stream stays in step, even when the
/// report does not spell it out.
#[cfg(feature = "cram")]
fn cram_skip_feature(
    compression: &CramCompressionHeader,
    decode: &mut CramDecode,
    code: u8,
    read_length: i32,
) -> Option<()> {
    match code {
        // A base and its quality score.
        b'B' => {
            let codec = compression.encoding(b"BA")?;
            decode.read_bytes(codec, 1)?;
            let codec = compression.encoding(b"QS")?;
            decode.read_bytes(codec, 1)?;
        }
        // A substitution code.
        b'X' => {
            let codec = compression.encoding(b"BS")?;
            decode.read_int(codec)?;
        }
        // The inserted bases.
        b'I' => {
            let codec = compression.encoding(b"IN")?;
            decode.read_bytes(codec, 0)?;
        }
        // The number of deleted bases.
        b'D' => {
            let codec = compression.encoding(b"DL")?;
            decode.read_int(codec)?;
        }
        // A single inserted base.
        b'i' => {
            let codec = compression.encoding(b"BA")?;
            decode.read_bytes(codec, 1)?;
        }
        // A single quality score.
        b'Q' => {
            let codec = compression.encoding(b"QS")?;
            decode.read_bytes(codec, 1)?;
        }
        // The number of skipped bases.
        b'N' => {
            let codec = compression.encoding(b"RS")?;
            decode.read_int(codec)?;
        }
        // The soft clipped bases.
        b'S' => {
            let codec = compression.encoding(b"SC")?;
            decode.read_bytes(codec, 0)?;
        }
        // The number of padded bases.
        b'P' => {
            let codec = compression.encoding(b"PD")?;
            decode.read_int(codec)?;
        }
        // The number of hard clipped bases.
        b'H' => {
            let codec = compression.encoding(b"HC")?;
            decode.read_int(codec)?;
        }
        _ => {
            let _ = read_length;
            return None;
        }
    }
    Some(())
}

/// The blocks of one slice: the compression header that governs it, the
/// slice header, the core data block and the external blocks.
#[cfg(feature = "cram")]
struct CramSlice {
    compression: CramCompressionHeader,
    header: CramSliceHeader,
    core: Vec<u8>,
    externals: Vec<(i32, Vec<u8>)>,
    /// The external blocks whose compression method this reader does not
    /// decode: their content id and their method.
    undecoded: Vec<(i32, u8)>,
}

/// The bytes of a block, decompressed when the method says so.
///
/// The methods are the ones the specifications give: raw and gzip in CRAM
/// 2.1, bzip2 from CRAM 2.0 on, lzma from CRAM 3.0 on -- the lzma method is
/// the xz container, not a bare LZMA stream -- and the rANS codec from CRAM
/// 3.0 on. The rest are compression schemes this reader does not carry, and a
/// block that uses one is left out rather than misread.
#[cfg(feature = "cram")]
fn cram_block_bytes(data: &[u8], block: &CramBlock) -> Option<Vec<u8>> {
    let payload = data.get(block.data_at..block.data_at.checked_add(block.data_len)?)?;
    // A block whose raw size is zero is empty whatever its method byte
    // says (CRAMv3 §8).
    if block.data_len == 0 {
        return Some(Vec::new());
    }
    match block.method {
        0 => Some(payload.to_vec()),
        1 => GzipReader::decode_bounded(payload, MAX_INFLATE)
            .ok()
            .map(|g| g.bytes),
        2 => {
            let mut decoder = Bzip2Decoder::new();
            decoder
                .decode_bounded(payload, MAX_INFLATE)
                .ok()
                .map(|b| b.bytes)
        }
        3 => XzReader::decompress_bounded(payload, MAX_INFLATE)
            .ok()
            .map(|x| x.bytes),
        4 => crate::cram_rans::decode(payload),
        5 => crate::cram_rans16::decode(payload),
        6 => crate::cram_arith::decode(payload),
        7 => crate::cram_fqz::decode(payload),
        8 => crate::cram_tokeniser::decode(payload, &|use_arith, compressed| {
            if use_arith {
                crate::cram_arith::decode(compressed)
            } else {
                crate::cram_rans16::decode(compressed)
            }
        }),
        _ => None,
    }
}

/// Read the slice a container's blocks hold, if it holds one.
#[cfg(feature = "cram")]
fn cram_read_slice(data: &[u8], blocks: &[CramBlock]) -> Option<CramSlice> {
    let compression_block = blocks.iter().find(|b| b.content_type == 1)?;
    let header_block = blocks.iter().find(|b| b.content_type == 2)?;
    let compression = cram_read_compression_header(&cram_block_bytes(data, compression_block)?)?;
    let header = cram_read_slice_header(&cram_block_bytes(data, header_block)?)?;
    let core = blocks
        .iter()
        .find(|b| b.content_type == 5)
        .and_then(|b| cram_block_bytes(data, b))
        .unwrap_or_default();
    let mut externals = Vec::new();
    let mut undecoded = Vec::new();
    for b in blocks.iter().filter(|b| b.content_type == 4) {
        match cram_block_bytes(data, b) {
            Some(bytes) => externals.push((b.content_id, bytes)),
            None => undecoded.push((b.content_id, b.method)),
        }
    }
    Some(CramSlice {
        compression,
        header,
        core,
        externals,
        undecoded,
    })
}

/// The details of a codec, for the report.
#[cfg(feature = "cram")]
fn cram_codec_detail(codec: &CramCodec) -> String {
    match codec {
        CramCodec::Null => "null: the data series is not preserved".to_string(),
        CramCodec::External { block_id } => {
            format!("external: the bytes are in external block {block_id}")
        }
        CramCodec::Golomb { offset, m } => {
            format!("golomb: offset {offset}, M {m}")
        }
        CramCodec::Huffman { alphabet, .. } => {
            format!("huffman: {} symbol(s)", alphabet.len())
        }
        CramCodec::ByteArrayLen { .. } => "byte array: the length is encoded first".to_string(),
        CramCodec::ByteArrayStop { stop, block_id } => {
            format!("byte array: terminated by {stop:#04x}, in external block {block_id}")
        }
        CramCodec::Beta { offset, bits } => {
            format!("beta: offset {offset}, {bits} bits")
        }
        CramCodec::Subexp { offset, k } => {
            format!("subexponential: offset {offset}, k {k}")
        }
        CramCodec::GolombRice { offset, log2m } => {
            format!("golomb-rice: offset {offset}, log2(m) {log2m}")
        }
        CramCodec::Gamma { offset } => format!("gamma: offset {offset}"),
    }
}

/// Read one block.
///
/// The block's header is the method, the content type and three ITF-8
/// sizes; then comes the data, and from CRAM 3 on a 4-byte CRC32. The
/// bytes the block occupies are the header, the data and that CRC32.
///
/// A header that claims more data than the file holds still parses: the
/// block is reported as far as it was read, because a truncated CRAM's
/// header block is exactly the part a search wants. `data_at` is absolute,
/// so it indexes the whole file rather than the slice the cursor was built
/// from.
#[cfg(feature = "cram")]
fn read_block(raw: &[u8], at: usize, edition: &CramEdition) -> Option<CramBlock> {
    let mut c = Cursor::new(raw.get(at..)?);
    let method = c.u8()?;
    let content_type = c.u8()?;
    let content_id = c.itf8()?;
    let comp_size = c.itf8()?;
    let raw_size = c.itf8()?;
    if comp_size < 0 || raw_size < 0 {
        return None;
    }
    let header_len = c.at;
    let data_at = at.checked_add(header_len)?;
    let data_len = (comp_size as usize).min(raw.len().saturating_sub(data_at));
    let total_len = header_len
        .checked_add(data_len)?
        .checked_add(if edition.crc32 { 4 } else { 0 })?;
    // From CRAM 3 on the block carries a CRC32 of the block's header and
    // its data as stored. A truncated block has no such bytes to hash, so
    // its CRC32 goes unchecked rather than being reported as a mismatch.
    let crc = if edition.crc32 {
        let end = data_at.checked_add(comp_size as usize)?;
        match raw.get(end..end.checked_add(4)?) {
            Some(stored) => Some(CramCrc {
                stored: u32::from_le_bytes(stored.try_into().ok()?),
                computed: crc32(raw.get(at..end)?),
            }),
            None => None,
        }
    } else {
        None
    };
    Some(CramBlock {
        method,
        content_type,
        content_id,
        raw_size,
        data_at,
        data_len,
        total_len,
        crc32: crc,
    })
}

/// Read the blocks of one container, as far as its count and its bytes
/// allow.
///
/// The count is the reader's only guide here, and a producer may disagree
/// with it, so a block that will not parse ends the list rather than the
/// walk: the container's `length` is what says where the container ends.
#[cfg(feature = "cram")]
fn read_container_blocks(
    raw: &[u8],
    at: usize,
    count: i32,
    edition: &CramEdition,
) -> Vec<CramBlock> {
    let mut blocks = Vec::new();
    let mut at = at;
    for _ in 0..count.max(0) {
        let Some(block) = read_block(raw, at, edition) else {
            break;
        };
        at = at.saturating_add(block.total_len);
        blocks.push(block);
    }
    blocks
}

/// The SAM header inside a file-header block.
///
/// The block's data is a 4-byte length and then the header text, which
/// may be padded with NULs (CRAMv3 §8.3). Only the raw and gzip methods
/// are decoded: the block's method is not negotiated, so claiming a header
/// this adapter could not read would be a guess.
#[cfg(feature = "cram")]
fn cram_header_text(data: &[u8], block: &CramBlock) -> Option<String> {
    let end = block.data_at.checked_add(block.data_len)?;
    let payload = data.get(block.data_at..end)?;
    let expanded: Vec<u8> = match block.method {
        0 => payload.to_vec(),
        1 => GzipReader::decode_bounded(payload, MAX_INFLATE).ok()?.bytes,
        _ => return None,
    };
    let mut c = Cursor::new(&expanded);
    let len = c.i32()?;
    if len < 0 {
        return None;
    }
    let text = c.take(len as usize)?;
    Some(cstring(text))
}

/// Describe a CRAM file: its version, its SAM header, and the number of
/// alignments its containers hold.
#[cfg(feature = "cram")]
fn describe_cram(data: &[u8]) -> Result<String> {
    if data.len() < 26 || data.get(..4) != Some(b"CRAM") {
        decline!("cram: no CRAM file definition (4-byte magic, major/minor, 20-byte id)");
    }
    let major = data[4];
    let minor = data[5];
    let mut out = String::new();
    let _ = writeln!(
        out,
        "cram {major}.{minor} alignment archive (uncompressed container stream)"
    );
    let _ = writeln!(out, "file id: {}", cstring(data.get(6..26).unwrap_or(&[])));

    let Some(edition) = cram_edition(major) else {
        bail!(
            "cram: CRAM {major}.{minor} is refused: {}",
            cram_edition_refusal(major)
        );
    };

    let Some(first) = read_container_header(data, 26, &edition) else {
        bail!("cram: the header container at byte 26 does not parse");
    };
    let _ = writeln!(
        out,
        "first container ({}):",
        if cram_is_eof(&first) {
            "the end-of-file marker"
        } else {
            "header container"
        }
    );
    let _ = writeln!(
        out,
        "  length {} byte(s) of blocks plus a {} byte(s) header, reference id {}, start {}, span {}, records {}, record counter {}, bases {}",
        first.length,
        first.header_len,
        first.ref_id,
        first.start,
        first.span,
        first.n_records,
        first.record_counter,
        first.bases
    );
    if !cram_is_eof(&first) {
        let _ = writeln!(
            out,
            "  reference id, start and span are ignored in the header container (CRAMv3 §7)"
        );
    }
    let blocks = read_container_blocks(data, 26 + first.header_len, first.n_blocks, &edition);
    let _ = writeln!(out, "  blocks: {}", blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        let _ = writeln!(
            out,
            "    {i}: method {}, content type {}, content id {}, {} raw byte(s) declared",
            cram_method_name(b.method),
            cram_content_name(b.content_type),
            b.content_id,
            b.raw_size
        );
    }
    match blocks.iter().find(|b| b.content_type == 0) {
        Some(block) => match cram_header_text(data, block) {
            Some(text) => write_block(&mut out, "sam header", &text),
            None => {
                let _ = writeln!(
                    out,
                    "sam header: the header block uses compression method {}, and the SAM header block may only be raw or gzip (CRAMv3 §8.3)",
                    block.method
                );
            }
        },
        None => {
            let _ = writeln!(
                out,
                "sam header: no file-header block in the first container"
            );
        }
    }

    // The CRC32s are counted as the walk goes, so the report says how many
    // were checked and which ones did not match. The walk reads the first
    // container again, so it — and its blocks — are counted there and not
    // here.
    let mut crc_headers = 0usize;
    let mut crc_headers_ok = 0usize;
    let mut crc_blocks = 0usize;
    let mut crc_blocks_ok = 0usize;
    let mut crc_bad: Vec<String> = Vec::new();
    let mut count_crc = |crc: Option<&CramCrc>, blocks: bool, where_: &str| {
        let Some(crc) = crc else { return };
        if blocks {
            crc_blocks += 1;
        } else {
            crc_headers += 1;
        }
        if crc.ok() {
            if blocks {
                crc_blocks_ok += 1;
            } else {
                crc_headers_ok += 1;
            }
        } else {
            crc_bad.push(format!(
                "{where_} carries {:08x} and its bytes hash to {:08x}",
                crc.stored, crc.computed
            ));
        }
    };

    // The alignment total comes from the container headers, each of which
    // states its own record count. The walk is bounded: totaling a 100 GB
    // CRAM would cost a pass over the file to produce one number.
    let mut at = 26usize;
    let mut containers = 0usize;
    let mut alignments = 0i64;
    let mut stop: Option<String> = None;
    let mut eof: Option<String> = None;
    let mut slices: Vec<CramSlice> = Vec::new();
    while containers < MAX_CRAMS_CONTAINERS {
        let Some(c) = read_container_header(data, at, &edition) else {
            stop = Some(format!("the container header at byte {at} does not parse"));
            break;
        };
        if cram_is_eof(&c) {
            // The end-of-file marker container: the last one in the file.
            eof = Some(cram_eof_marker_note(data, at, &c));
            break;
        }
        containers += 1;
        alignments += i64::from(c.n_records.max(0));
        count_crc(
            c.crc32.as_ref(),
            false,
            &format!("the container header at byte {at}"),
        );
        // The blocks of a container are read for their CRC32 and for the
        // slice they may hold; they are not listed, because a CRAM has a
        // great many of them.
        let container_blocks = read_container_blocks(data, at + c.header_len, c.n_blocks, &edition);
        for b in &container_blocks {
            count_crc(
                b.crc32.as_ref(),
                true,
                &format!("a block of the container at byte {at}"),
            );
        }
        if let Some(slice) = cram_read_slice(data, &container_blocks) {
            slices.push(slice);
        }
        let Some(next) = at
            .checked_add(c.header_len)
            .and_then(|h| h.checked_add(c.length as usize))
        else {
            stop = Some(format!(
                "the container at byte {at} declares a size that does not fit"
            ));
            break;
        };
        if next <= at {
            stop = Some(format!(
                "the container at byte {at} declares a size that does not move forward"
            ));
            break;
        }
        if next >= data.len() {
            stop = Some(format!(
                "the file holds no container after the one at byte {at}"
            ));
            break;
        }
        at = next;
    }
    let _ = writeln!(out, "containers walked: {containers}");
    let _ = writeln!(out, "alignments in those containers: {alignments}");
    if !slices.is_empty() {
        let _ = writeln!(out, "slices: {}", slices.len());
        for slice in &slices {
            cram_write_slice(&mut out, slice);
        }
    }
    if let Some(note) = eof {
        let _ = writeln!(out, "end-of-file marker: {note}");
    }
    if containers >= MAX_CRAMS_CONTAINERS {
        let _ = writeln!(
            out,
            "note: the container walk stopped at the {MAX_CRAMS_CONTAINERS}-container cap"
        );
    }
    if let Some(reason) = stop {
        let _ = writeln!(out, "note: the container walk stopped: {reason}");
    }
    if edition.crc32 {
        let _ = writeln!(
            out,
            "crc32: {crc_headers} container header(s) and {crc_blocks} block(s) checked, {crc_headers_ok} and {crc_blocks_ok} verified"
        );
        for bad in &crc_bad {
            let _ = writeln!(out, "crc32 MISMATCH: {bad}");
        }
    } else {
        let _ = writeln!(out, "crc32: this edition has no CRC32 to verify");
    }
    if !slices.is_empty() {
        let _ = writeln!(
            out,
            "not decoded: the bases of a mapped read (they are reconstructed from the reference, which this reader does not carry)"
        );
    }
    Ok(out)
}

#[cfg(test)]
#[cfg(any(feature = "bam", feature = "bcf", feature = "cram", feature = "sam"))]
mod tests {
    //! Fixtures are assembled byte by byte from the specification tables in
    //! the module header, never from a captured real file: a fixture built
    //! by hand is the only one that proves the parser reads the *spec*, and
    //! a disagreement then has to be settled against the spec rather than
    //! against whatever the parser happened to accept.
    //!
    //! Two properties get first-class tests because they are the classic
    //! failures of this file family: a BGZF stream is *many* gzip members,
    //! and a truncated container must still yield what it did hold.

    use super::*;
    use rgx_core::compress::GzipWriter;

    // ---- BGZF writer (SAMv1 §4.1) -----------------------------------------

    /// One BGZF block: a gzip member whose FEXTRA carries the `BC` subfield
    /// holding the total block size minus one. `GzipWriter` emits the
    /// member without it, so the header is rebuilt here — which is also
    /// what makes these fixtures fail if the adapter ever stops requiring
    /// that subfield.
    #[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
    fn bgzf_member(payload: &[u8]) -> Vec<u8> {
        let gz = GzipWriter::new().encode(payload);
        let deflated = gz.get(10..).expect("gzip body");
        let total = 18 + deflated.len();
        assert!(
            total <= 1 << 16,
            "fixture payload does not fit one BGZF block"
        );
        let mut out = Vec::new();
        out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x04]); // FEXTRA
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mtime
        out.extend_from_slice(&[0x00, 0xff]); // xfl, os unknown
        out.extend_from_slice(&6u16.to_le_bytes()); // xlen
        out.extend_from_slice(b"BC");
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&((total - 1) as u16).to_le_bytes());
        out.extend_from_slice(deflated);
        out
    }

    /// A payload split across `blocks` BGZF members, closed with the
    /// 28-byte EOF marker. Splitting mid-record is the point: it is what a
    /// single-member assumption silently truncates.
    #[cfg(any(feature = "bam", feature = "bcf", feature = "sam"))]
    fn bgzf_stream(payload: &[u8], blocks: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let chunk = payload.len().div_ceil(blocks).max(1);
        for part in payload.chunks(chunk) {
            out.extend_from_slice(&bgzf_member(part));
        }
        out.extend_from_slice(&BGZF_EOF_MARKER);
        out
    }

    // ---- BAM writer (SAMv1 §4.2) -----------------------------------------

    #[cfg(feature = "bam")]
    fn bam_header(header: &str, refs: &[(&str, u32)]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"BAM\x01");
        v.extend_from_slice(&(header.len() as u32).to_le_bytes());
        v.extend_from_slice(header.as_bytes());
        v.extend_from_slice(&(refs.len() as u32).to_le_bytes());
        for (name, len) in refs {
            v.extend_from_slice(&((name.len() + 1) as u32).to_le_bytes());
            v.extend_from_slice(name.as_bytes());
            v.push(0);
            v.extend_from_slice(&len.to_le_bytes());
        }
        v
    }

    #[cfg(feature = "bam")]
    fn cigar_words(cigar: &str) -> Vec<u32> {
        // `*` is SAM's "no CIGAR", stored as n_cigar_op = 0.
        if cigar == "*" || cigar.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut len = 0u32;
        for &b in cigar.as_bytes() {
            if b.is_ascii_digit() {
                len = len * 10 + u32::from(b - b'0');
            } else {
                let op = CIGAR_OPS
                    .iter()
                    .position(|&o| o == b)
                    .expect("fixture cigar operator is in MIDNSHP=X");
                out.push((len << 4) | op as u32);
                len = 0;
            }
        }
        out
    }

    #[cfg(feature = "bam")]
    fn bam_record(qname: &str, ref_id: i32, pos: i32, mapq: u8, flag: u16, cigar: &str) -> Vec<u8> {
        let words = cigar_words(cigar);
        let l_seq = 8u32;
        let mut body = Vec::new();
        body.extend_from_slice(&ref_id.to_le_bytes());
        body.extend_from_slice(&pos.to_le_bytes());
        body.push(qname.len() as u8 + 1);
        body.push(mapq);
        body.extend_from_slice(&0u16.to_le_bytes()); // bin
        body.extend_from_slice(&(words.len() as u16).to_le_bytes());
        body.extend_from_slice(&flag.to_le_bytes());
        body.extend_from_slice(&l_seq.to_le_bytes());
        body.extend_from_slice(&(-1i32).to_le_bytes()); // next_refID
        body.extend_from_slice(&(-1i32).to_le_bytes()); // next_pos
        body.extend_from_slice(&0i32.to_le_bytes()); // tlen
        body.extend_from_slice(qname.as_bytes());
        body.push(0);
        for w in &words {
            body.extend_from_slice(&w.to_le_bytes());
        }
        body.extend_from_slice(&[0u8; 4]); // 4-bit bases for l_seq = 8
        body.extend_from_slice(&[0xffu8; 8]); // qualities
        let mut v = (body.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&body);
        v
    }

    #[cfg(feature = "bam")]
    const REFS: [(&str, u32); 2] = [("chr1", 248_956_422), ("GL000207.1", 4_262_839)];

    #[cfg(feature = "bam")]
    fn bam_payload() -> Vec<u8> {
        let mut p = bam_header(
            "@HD\tVN:1.6\tSO:coordinate\n@SQ\tSN:chr1\tLN:248956422\n@SQ\tSN:GL000207.1\tLN:4262839\n@RG\tID:lane1\tSM:NA12878\n",
            &REFS,
        );
        p.extend_from_slice(&bam_record("read001", 0, 1000, 60, 0x1 | 0x2, "100M"));
        p.extend_from_slice(&bam_record("read002", 0, 2000, 40, 0x1 | 0x20, "50M50S"));
        p.extend_from_slice(&bam_record("read003", 1, 77, 0, 0x1 | 0x8, "77M"));
        p.extend_from_slice(&bam_record("read004", -1, -1, 0, 0x1 | 0x4, "*"));
        p
    }

    #[cfg(feature = "bam")]
    fn bam_report(data: &[u8]) -> String {
        describe_bam(data).expect("bam decodes")
    }

    // ---- BCF writers ------------------------------------------------------

    #[cfg(feature = "bcf")]
    fn bcf2_payload() -> Vec<u8> {
        let text = "##fileformat=VCFv4.2\n##contig=<ID=chr1,length=248956422>\n##INFO=<ID=DP,Number=1,Type=Integer,Description=\"depth\">\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tNA12878\n";
        let mut p = Vec::new();
        p.extend_from_slice(b"BCF\x02\x02");
        p.extend_from_slice(&((text.len() as i32 + 1).to_le_bytes()));
        p.extend_from_slice(text.as_bytes());
        p.push(0);
        for i in 0..3u8 {
            p.extend_from_slice(&12i32.to_le_bytes()); // l_shared
            p.extend_from_slice(&[i; 12]);
            p.extend_from_slice(&4i32.to_le_bytes()); // l_indiv
            p.extend_from_slice(&[0u8; 4]);
        }
        p
    }

    #[cfg(feature = "bcf")]
    fn bcf1_payload() -> Vec<u8> {
        let seqnm = "chr1\0GL000207.1\0";
        let meta = "fileformat=VCFv4.1\0contig=<ID=chr1>\0";
        let mut p = Vec::new();
        p.extend_from_slice(b"BCF\x04");
        p.extend_from_slice(&(seqnm.len() as i32).to_le_bytes());
        p.extend_from_slice(seqnm.as_bytes());
        p.extend_from_slice(&1i32.to_le_bytes()); // l_smpl
        p.extend_from_slice(&(meta.len() as i32).to_le_bytes());
        p.extend_from_slice(meta.as_bytes());
        p.extend_from_slice(&8i32.to_le_bytes()); // l_shared
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&0i32.to_le_bytes()); // l_indiv
        p
    }

    // ---- CRAM writers -----------------------------------------------------

    /// htslib's `itf8_put`: the width test is on the value's *raw bit
    /// pattern*, not on a signed range, which is why `-1` is the 5-byte
    /// `ff ff ff ff 0f` rather than something the 2-byte form could hold.
    #[cfg(feature = "cram")]
    fn itf8_put(v: i32) -> Vec<u8> {
        let u = v as u32;
        if u & !0x0000_007f == 0 {
            vec![(u & 0x7f) as u8]
        } else if u & !0x0000_3fff == 0 {
            vec![(((u >> 8) & 0x3f) as u8) | 0x80, (u & 0xff) as u8]
        } else if u & !0x001f_ffff == 0 {
            vec![
                (((u >> 16) & 0x1f) as u8) | 0xc0,
                ((u >> 8) & 0xff) as u8,
                (u & 0xff) as u8,
            ]
        } else if u & !0x0fff_ffff == 0 {
            vec![
                (((u >> 24) & 0x0f) as u8) | 0xe0,
                ((u >> 16) & 0xff) as u8,
                ((u >> 8) & 0xff) as u8,
                (u & 0xff) as u8,
            ]
        } else {
            vec![
                ((u >> 28) as u8) | 0xf0,
                ((u >> 20) & 0xff) as u8,
                ((u >> 12) & 0xff) as u8,
                ((u >> 4) & 0xff) as u8,
                (u & 0x0f) as u8,
            ]
        }
    }

    #[cfg(feature = "cram")]
    fn ltf8_put(v: u64) -> Vec<u8> {
        if v < 0x80 {
            vec![v as u8]
        } else if v < 0x4000 {
            vec![((v >> 8) as u8) | 0x80, (v & 0xff) as u8]
        } else if v < 0x200000 {
            vec![
                ((v >> 16) as u8) | 0xc0,
                ((v >> 8) & 0xff) as u8,
                (v & 0xff) as u8,
            ]
        } else if v < 0x1000_0000 {
            vec![
                ((v >> 24) as u8) | 0xe0,
                ((v >> 16) & 0xff) as u8,
                ((v >> 8) & 0xff) as u8,
                (v & 0xff) as u8,
            ]
        } else {
            vec![
                ((v >> 32) as u8) | 0xf0,
                ((v >> 24) & 0xff) as u8,
                ((v >> 16) & 0xff) as u8,
                ((v >> 8) & 0xff) as u8,
                (v & 0xff) as u8,
            ]
        }
    }

    /// The CRC32 a CRAM 3 container header or block carries: the hash of the
    /// bytes it covers, stored little-endian.
    #[cfg(feature = "cram")]
    fn cram_crc32(bytes: &[u8]) -> [u8; 4] {
        crc32(bytes).to_le_bytes()
    }

    /// A block of a CRAM 3 container.
    #[cfg(feature = "cram")]
    fn cram_block(method: u8, content_type: u8, content_id: i32, data: &[u8]) -> Vec<u8> {
        cram_block_edition(3, method, content_type, content_id, data)
    }

    /// A block whose stored CRC32 is wrong, so the check has something to
    /// fail on. The last byte of the block is the low byte of its CRC32.
    #[cfg(feature = "cram")]
    fn cram_block_with_bad_crc(
        method: u8,
        content_type: u8,
        content_id: i32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = cram_block(method, content_type, content_id, data);
        let last = v.len() - 1;
        v[last] ^= 0xff;
        v
    }

    /// A block of one edition: CRAM 3 added the CRC32 that follows a
    /// block's data, and CRAM 2 has none. The CRC32 covers the block's
    /// header and its data as stored.
    #[cfg(feature = "cram")]
    fn cram_block_edition(
        major: u8,
        method: u8,
        content_type: u8,
        content_id: i32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut v = vec![method, content_type];
        v.extend_from_slice(&itf8_put(content_id));
        v.extend_from_slice(&itf8_put(data.len() as i32)); // compressed size
        v.extend_from_slice(&itf8_put(data.len() as i32)); // raw size
        v.extend_from_slice(data);
        if major >= 3 {
            let sum = cram_crc32(&v);
            v.extend_from_slice(&sum);
        }
        v
    }

    #[cfg(feature = "cram")]
    fn cram_container(blocks: &[Vec<u8>], n_records: i32) -> Vec<u8> {
        cram_container_edition(3, blocks, n_records)
    }

    /// A container of one edition: CRAM 2's record counter is an ITF-8
    /// where CRAM 3's is an LTF-8, and CRAM 3 added the CRC32 that follows
    /// the container header. That CRC32 covers the header's own bytes.
    #[cfg(feature = "cram")]
    fn cram_container_edition(major: u8, blocks: &[Vec<u8>], n_records: i32) -> Vec<u8> {
        let length: usize = blocks.iter().map(|b| b.len()).sum();
        let mut v = Vec::new();
        v.extend_from_slice(&(length as i32).to_le_bytes());
        v.extend_from_slice(&itf8_put(0)); // reference id
        v.extend_from_slice(&itf8_put(0)); // start
        v.extend_from_slice(&itf8_put(0)); // span
        v.extend_from_slice(&itf8_put(n_records));
        if major >= 3 {
            v.extend_from_slice(&ltf8_put(0)); // record counter
        } else {
            v.extend_from_slice(&itf8_put(0)); // record counter
        }
        v.extend_from_slice(&ltf8_put(0)); // bases
        v.extend_from_slice(&itf8_put(blocks.len() as i32));
        v.extend_from_slice(&itf8_put(blocks.len() as i32)); // num_landmarks
        for b in blocks {
            v.extend_from_slice(&itf8_put(0)); // landmark offset
            let _ = b;
        }
        if major >= 3 {
            let sum = cram_crc32(&v);
            v.extend_from_slice(&sum);
        }
        for b in blocks {
            v.extend_from_slice(b);
        }
        v
    }

    #[cfg(feature = "cram")]
    fn cram_file_def(id: &str) -> Vec<u8> {
        cram_file_def_edition(3, 0, id)
    }

    #[cfg(feature = "cram")]
    fn cram_file_def_edition(major: u8, minor: u8, id: &str) -> Vec<u8> {
        let mut v = b"CRAM".to_vec();
        v.push(major);
        v.push(minor);
        let mut field = id.as_bytes().to_vec();
        field.resize(20, b'\0');
        v.extend_from_slice(&field);
        v
    }

    #[cfg(feature = "cram")]
    fn sam_header_block(method: u8, text: &str) -> Vec<u8> {
        sam_header_block_edition(3, method, text)
    }

    #[cfg(feature = "cram")]
    fn sam_header_block_edition(major: u8, method: u8, text: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(text.len() as i32).to_le_bytes());
        payload.extend_from_slice(text.as_bytes());
        let stored = if method == 1 {
            GzipWriter::new().encode(&payload)
        } else {
            payload
        };
        cram_block_edition(major, method, 0, 0, &stored)
    }

    #[cfg(feature = "cram")]
    fn cram_report(data: &[u8]) -> String {
        describe_cram(data).expect("cram decodes")
    }

    // ---- BGZF -------------------------------------------------------------

    #[test]
    #[cfg(feature = "bam")]
    fn a_gzip_member_without_the_bc_subfield_has_no_bgzf_length() {
        let plain = GzipWriter::new().encode(b"plain gzip, no extra field");
        assert_eq!(bgzf_member_len(&plain), None);
        assert_eq!(bgzf_member_len(b"\x1f\x8b\x08\x04truncated"), None);
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bgzf_member_length_is_the_bsize_field_plus_one() {
        let member = bgzf_member(b"payload");
        assert_eq!(bgzf_member_len(&member), Some(member.len()));
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bgzf_stream_reports_its_blocks_and_its_eof_marker() {
        let (payload, walk) = inflate_bgzf(&bgzf_stream(&bam_payload(), 3), MAX_INFLATE);
        assert_eq!(
            payload,
            bam_payload(),
            "multi-member stream must reassemble"
        );
        assert_eq!(walk.blocks, 4, "three payload blocks plus the EOF marker");
        assert!(walk.eof_marker);
        assert!(walk.note.is_none());
    }

    // ---- BAM --------------------------------------------------------------

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_names_its_header_references_and_alignments() {
        let report = bam_report(&bgzf_stream(&bam_payload(), 1));
        assert!(report.contains("chr1\t248956422"), "{report}");
        assert!(report.contains("@RG\tID:lane1\tSM:NA12878"), "{report}");
        assert!(report.contains("alignment records: 4"), "{report}");
        assert!(
            report.contains("read001\tchr1:1001\tmapq 60\t100M"),
            "{report}"
        );
        assert!(report.contains("50M50S"), "{report}");
        assert!(report.contains("not decoded: base sequences"), "{report}");
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_reports_the_flag_breakdown_and_the_references_reads_map_to() {
        let report = bam_report(&bgzf_stream(&bam_payload(), 1));
        assert!(report.contains("paired 4"), "{report}");
        assert!(report.contains("proper-pair 1"), "{report}");
        assert!(report.contains("unmapped 1"), "{report}");
        assert!(report.contains("GL000207.1\t1"), "{report}");
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_split_across_three_bgzf_blocks_reads_as_one_stream() {
        // The payload is cut mid-record on purpose: a decoder that treats
        // the file as one gzip member sees three half-members and reports
        // nothing useful here.
        let report = bam_report(&bgzf_stream(&bam_payload(), 3));
        assert!(report.contains("alignment records: 4"), "{report}");
        assert!(
            report.contains("read004\tunmapped\tmapq 0\t*"),
            "an unmapped read carries no reference and no CIGAR: {report}"
        );
        assert!(report.contains("bgzf: 4 block(s)"), "{report}");
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_cut_inside_its_last_block_still_reports_what_it_held() {
        let full = bgzf_stream(&bam_payload(), 2);
        let cut = &full[..full.len() - 40];
        let report = bam_report(cut);
        assert!(report.contains("references: 2"), "{report}");
        assert!(report.contains("EOF marker absent"), "{report}");
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_with_a_record_whose_block_size_is_too_small_stops_the_walk() {
        let mut payload = bam_header("@HD\tVN:1.6\n", &REFS);
        payload.extend_from_slice(&bam_record("read001", 0, 10, 60, 0, "10M"));
        payload.extend_from_slice(&bam_record("read002", 0, 20, 60, 0, "10M"));
        let last = payload.len();
        payload.extend_from_slice(&bam_record("read003", 0, 30, 60, 0, "10M"));
        // block_size = 4: under the 32-byte fixed part, and a length the
        // walk must refuse rather than use to slice the rest of the file.
        payload[last..last + 4].copy_from_slice(&4u32.to_le_bytes());

        let report = bam_report(&bgzf_stream(&payload, 1));
        assert!(report.contains("under the 32-byte fixed part"), "{report}");
        assert!(report.contains("alignment records: 2"), "{report}");
    }

    #[test]
    #[cfg(feature = "bam")]
    fn a_bam_whose_header_length_past_the_stream_bails() {
        let mut payload = bam_header("@HD\tVN:1.6\n", &REFS);
        payload.truncate(12);
        let err = describe_bam(&bgzf_stream(&payload, 1)).expect_err("must bail");
        assert!(format!("{err}").contains("bam:"), "{err}");
    }

    #[test]
    #[cfg(all(feature = "bam", feature = "sam"))]
    fn a_gzipped_sam_bails_so_the_next_adapter_can_try() {
        let sam = "@HD\tVN:1.6\tSO:coordinate\nr1\t0\tchr1\t1\t60\t1M\t*\t0\t0\tA\tI\n";
        let err = describe_bam(&bgzf_stream(sam.as_bytes(), 1)).expect_err("must bail");
        assert!(format!("{err}").contains("gzipped SAM"), "{err}");
    }

    #[test]
    #[cfg(all(feature = "bam", feature = "bcf", feature = "cram"))]
    fn bytes_that_are_not_gzip_at_all_bail() {
        assert!(describe_bam(b"not a bam at all").is_err());
        assert!(describe_bcf(b"not a bcf at all").is_err());
        assert!(describe_cram(b"not a cram at all").is_err());
        assert!(describe_cram(b"CRAM\x03\x00short").is_err());
    }

    // ---- SAM ---------------------------------------------------------------

    #[cfg(feature = "sam")]
    const SAM_TEXT: &[u8] = b"@HD\tVN:1.6\tSO:unsorted\n\
@SQ\tSN:chr7\tLN:159345973\n\
r1\t0\tchr7\t55271500\t255\t5S90M\t*\t0\t0\tTTTTACCTA\tRGXFILLER\n\
r2\t0\tchr7\t55271600\t255\t5S90M\t*\t0\t0\tGGGGTTCCA\tRGXFILLER\n";

    #[test]
    #[cfg(feature = "sam")]
    fn a_bgzf_sam_yields_its_header_and_its_records() {
        let data = bgzf_stream(SAM_TEXT, 2);
        let Outcome::Text(t) = Sam.extract(&data, "aln.sam").expect("a BGZF sam is ours") else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("@SQ\tSN:chr7"), "the header line: {s}");
        assert!(s.contains("BGZF-compressed"), "{s}");
        // Splitting mid-record across blocks is what a single-member
        // assumption truncates, so the walk has to reassemble it.
        assert_eq!(s.matches("RGXFILLER").count(), 2, "{s}");
    }

    #[test]
    #[cfg(feature = "sam")]
    fn a_plain_text_sam_is_declined_so_the_raw_path_keeps_it() {
        // The subset property as a test: if this answered, rgx would search
        // something other than the file's own lines.
        assert!(!GzipReader::is_gzip(SAM_TEXT), "the fixture is plain text");
        assert!(Sam.extract(SAM_TEXT, "aln.sam").is_err());
    }

    #[test]
    #[cfg(feature = "sam")]
    fn a_gzipped_sam_without_the_bgzf_subfield_is_still_read() {
        // `gzip aln.sam` writes a gzip member with no `BC` subfield. The
        // block walk correctly refuses to guess a boundary there, so the
        // whole-member reader has to answer or the file would go dark.
        let data = GzipWriter::new().encode(SAM_TEXT);
        assert!(
            bgzf_member_len(&data).is_none(),
            "a plain gzip member carries no BC subfield"
        );
        let Outcome::Text(t) = Sam.extract(&data, "aln.sam").expect("gzip sam is ours") else {
            panic!("text")
        };
        let s = String::from_utf8(t).unwrap();
        assert!(s.contains("gzip-compressed, not BGZF"), "{s}");
        assert!(s.contains("@SQ\tSN:chr7"), "{s}");
        assert!(s.contains("RGXFILLER"), "{s}");
    }

    #[test]
    #[cfg(all(feature = "bam", feature = "sam"))]
    fn a_bam_and_a_compressed_sam_do_not_answer_for_each_other() {
        // Same container, different payload. The BAM reader's bail is what
        // lets `Sam` answer, and this holds down both halves.
        let bam = bgzf_stream(&bam_header("@HD\tVN:1.6\n", &[("chr7", 159_345_973)]), 1);
        assert!(
            describe_bam(&bam).is_ok(),
            "BAM still answers for its own file"
        );
        let Outcome::Text(t) = Sam.extract(&bam, "x.sam").expect("still a stream") else {
            panic!("text")
        };
        assert!(
            String::from_utf8(t).unwrap().contains("BAM\x01"),
            "the payload comes back as bytes; decoding it is BAM's job, not ours"
        );
    }

    #[test]
    #[cfg(feature = "sam")]
    fn sam_never_panics_on_arbitrary_bytes() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![
                ("bgzf", bgzf_stream(SAM_TEXT, 3)),
                ("gzip", GzipWriter::new().encode(SAM_TEXT)),
                ("magic-only", vec![0x1f, 0x8b, 0x08, 0x04]),
                ("empty", vec![]),
            ],
            500,
            "sam",
            |data| {
                let _ = Sam.extract(data, "aln.sam");
            },
        );
    }

    // ---- BCF --------------------------------------------------------------

    #[test]
    #[cfg(feature = "bcf")]
    fn a_bcf2_reports_the_vcf_header_and_counts_its_records() {
        let report = describe_bcf(&bgzf_stream(&bcf2_payload(), 2)).expect("bcf decodes");
        assert!(report.contains("bcf 2.2"), "{report}");
        assert!(
            report.contains("##contig=<ID=chr1,length=248956422>"),
            "{report}"
        );
        assert!(report.contains("sample columns: 1"), "{report}");
        assert!(report.contains("variant records: 3"), "{report}");
    }

    #[test]
    #[cfg(feature = "bcf")]
    fn a_bcf1_reports_its_sequence_dictionary_and_meta_lines() {
        let report = describe_bcf(&bgzf_stream(&bcf1_payload(), 1)).expect("bcf decodes");
        assert!(
            report.contains("sequence dictionary: 2 name(s)"),
            "{report}"
        );
        assert!(report.contains("GL000207.1"), "{report}");
        assert!(report.contains("fileformat=VCFv4.1"), "{report}");
        assert!(report.contains("samples: 1"), "{report}");
    }

    #[test]
    #[cfg(feature = "bcf")]
    fn a_bcf_whose_record_length_past_the_stream_stops_the_walk() {
        let mut payload = bcf2_payload();
        let cut = payload.len() - 8;
        payload[cut..cut + 4].copy_from_slice(&9999i32.to_le_bytes());
        let report = describe_bcf(&bgzf_stream(&payload, 1)).expect("header still decodes");
        assert!(report.contains("variant records: 2"), "{report}");
        assert!(report.contains("note: record walk stopped"), "{report}");
    }

    #[test]
    #[cfg(feature = "bcf")]
    fn a_gzipped_vcf_bails_so_the_next_adapter_can_try() {
        let vcf = "##fileformat=VCFv4.2\n#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\n";
        let err = describe_bcf(&bgzf_stream(vcf.as_bytes(), 1)).expect_err("must bail");
        assert!(format!("{err}").contains("gzipped VCF"), "{err}");
    }

    // ---- CRAM -------------------------------------------------------------

    #[test]
    #[cfg(feature = "cram")]
    fn itf8_decodes_the_specifications_worked_examples() {
        // CRAMv3 §10.1: `e0 45 4f 46` is 4542278 and `ff ff ff ff 0f`
        // is -1 — the second is why the 5-byte form ends on 4 bits.
        assert_eq!(itf8_get(&[0xe0, 0x45, 0x4f, 0x46]), Some((4_542_278, 4)));
        assert_eq!(itf8_get(&[0xff, 0xff, 0xff, 0xff, 0x0f]), Some((-1, 5)));
        assert_eq!(itf8_get(&[0x2a]), Some((42, 1)));
        assert_eq!(
            itf8_get(&[0xff]),
            None,
            "a 5-byte prefix with none of its bytes after it"
        );
        assert_eq!(itf8_get(&[0xc0]), None, "a prefix with no bytes after it");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn itf8_and_ltf8_round_trip_every_prefix_width() {
        for v in [
            0i32,
            1,
            63,
            64,
            127,
            -1,
            454,
            4542,
            4542278,
            -4542278,
            i32::MAX,
        ] {
            let bytes = itf8_put(v);
            assert_eq!(itf8_get(&bytes), Some((v, bytes.len())), "itf8 {v}");
        }
        for v in [
            0u64,
            1,
            0x3f,
            0x40,
            0x1f_ffff,
            0x20_0000,
            u64::from(u32::MAX),
        ] {
            let bytes = ltf8_put(v);
            assert_eq!(ltf8_get(&bytes), Some((v, bytes.len())), "ltf8 {v}");
        }
        assert_eq!(ltf8_get(&[0xff]), None, "the 0xff prefix is reserved");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_reports_its_version_file_id_and_sam_header() {
        let mut f = cram_file_def("NA12878.cram");
        let header = "@HD\tVN:1.6\tSO:coordinate\n@SQ\tSN:chr1\tLN:248956422\n";
        f.extend_from_slice(&cram_container(&[sam_header_block(0, header)], 0));
        let report = cram_report(&f);
        assert!(report.contains("cram 3.0"), "{report}");
        assert!(report.contains("file id: NA12878.cram"), "{report}");
        assert!(report.contains("@SQ\tSN:chr1\tLN:248956422"), "{report}");
        assert!(report.contains("content type file header"), "{report}");
        assert!(
            report.contains("crc32: 1 container header(s) and 1 block(s) checked"),
            "{report}"
        );
        assert!(report.contains("1 and 1 verified"), "{report}");
        assert!(!report.contains("crc32 MISMATCH"), "{report}");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_whose_crc32_does_not_match_its_bytes_says_so_by_name() {
        // The fixtures' CRC32s are the real ones, so corrupting one turns
        // the check into a named mismatch instead of a silent pass.
        let header = "@HD\tVN:1.6\n";
        let mut f = cram_file_def("bad-crc.cram");
        f.extend_from_slice(&cram_container(
            &[
                sam_header_block(0, header),
                cram_block_with_bad_crc(0, 4, 1, &[0u8; 20]),
            ],
            0,
        ));
        let report = cram_report(&f);
        assert!(
            report.contains("crc32: 1 container header(s) and 2 block(s) checked"),
            "{report}"
        );
        assert!(report.contains("1 and 1 verified"), "{report}");
        assert!(
            report.contains("crc32 MISMATCH: a block of the container at byte 26 carries"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_whose_header_block_is_gzipped_is_still_decoded() {
        let mut f = cram_file_def("gzip-header.cram");
        let header = "@HD\tVN:1.6\n@RG\tID:lane1\tSM:NA12878\n";
        f.extend_from_slice(&cram_container(&[sam_header_block(1, header)], 0));
        let report = cram_report(&f);
        assert!(report.contains("@RG\tID:lane1\tSM:NA12878"), "{report}");
        assert!(report.contains("method gzip"), "{report}");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_alignment_count_sums_the_data_containers_record_counts() {
        let header = "@HD\tVN:1.6\n";
        let mut f = cram_file_def("counts.cram");
        f.extend_from_slice(&cram_container(&[sam_header_block(0, header)], 0));
        f.extend_from_slice(&cram_container(&[cram_block(4, 4, 1, &[0u8; 32])], 12));
        f.extend_from_slice(&cram_container(&[cram_block(4, 5, 1, &[0u8; 64])], 7));
        let report = cram_report(&f);
        assert!(report.contains("containers walked: 3"), "{report}");
        assert!(
            report.contains("alignments in those containers: 19"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_with_a_header_block_in_a_compression_we_do_not_decode_says_so() {
        let mut f = cram_file_def("bzip2-header.cram");
        let mut payload = Vec::new();
        payload.extend_from_slice(&5i32.to_le_bytes());
        payload.extend_from_slice(b"@HD\n");
        f.extend_from_slice(&cram_container(&[cram_block(2, 0, 0, &payload)], 0));
        let report = cram_report(&f);
        assert!(
            report
                .contains("compression method 2, and the SAM header block may only be raw or gzip"),
            "{report}"
        );
    }

    /// A block whose data is compressed with a method the reader decodes
    /// comes back whole: bzip2, which CRAM has carried since 2.0, and the
    /// xz container, which is what CRAM 3.0's lzma method is.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_bzip2_or_xz_is_decoded() {
        let mut encoder = rgx_core::compress::bzip2::Bzip2Encoder::new();
        let stored = encoder.encode(b"the block's bytes");
        let block = CramBlock {
            method: 2,
            content_type: 4,
            content_id: 1,
            raw_size: 16,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(&stored, &block).as_deref(),
            Some(&b"the block's bytes"[..]),
            "the bzip2 block is not decoded"
        );

        // The xz container of the core's own fixture: its plain side is the
        // sentence below.
        const XZ: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x02, 0x00,
            0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0x01, 0x00, 0x3b, 0x72,
            0x67, 0x78, 0x20, 0x78, 0x7a, 0x20, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x3a,
            0x20, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f,
            0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f,
            0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64,
            0x6f, 0x67, 0x0a, 0x00, 0x04, 0x2f, 0x24, 0x8c, 0x00, 0x01, 0x50, 0x3c, 0xf8, 0x94,
            0x52, 0xb5, 0x90, 0x42, 0x99, 0x0d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x59, 0x5a,
        ];
        let block = CramBlock {
            method: 3,
            content_type: 4,
            content_id: 1,
            raw_size: 60,
            data_at: 0,
            data_len: XZ.len(),
            total_len: XZ.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(XZ, &block).as_deref(),
            Some(&b"rgx xz fixture: the quick brown fox jumps over the lazy dog\n"[..]),
            "the xz block is not decoded"
        );
    }

    /// A block whose data is compressed with the rANS codec of CRAM 3.0 comes
    /// back whole: the frame of the reference implementation decodes to the
    /// bytes it was written from.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_rans_is_decoded() {
        let stored = crate::cram_rans::ORDER0;
        let block = CramBlock {
            method: 4,
            content_type: 4,
            content_id: 1,
            raw_size: 11,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(stored, &block).as_deref(),
            Some(&b"abracadabra"[..]),
            "the rANS block is not decoded"
        );
    }

    /// A block whose data is compressed with the adaptive arithmetic of CRAM 3.1
    /// comes back whole: the frame of the reference implementation decodes to the
    /// bytes it was written from.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_arithmetic_is_decoded() {
        let stored = crate::cram_arith::ORDER0;
        let block = CramBlock {
            method: 6,
            content_type: 4,
            content_id: 1,
            raw_size: 45,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(stored, &block).as_deref(),
            Some(&b"abracadabraabracadabraabracadabraabracadabrad"[..]),
            "the arithmetic block is not decoded"
        );
    }

    /// A block whose data is compressed with the rANS Nx16 codec of CRAM 3.1
    /// comes back whole: the frame of the reference implementation decodes to the
    /// bytes it was written from.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_rans16_is_decoded() {
        let stored = crate::cram_rans16::ORDER0;
        let block = CramBlock {
            method: 5,
            content_type: 4,
            content_id: 1,
            raw_size: 45,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(stored, &block).as_deref(),
            Some(&b"abracadabraabracadabraabracadabraabracadabrad"[..]),
            "the rANS Nx16 block is not decoded"
        );
    }

    /// A block whose data is compressed with the name tokeniser of CRAM 3.1
    /// comes back whole: the frame of the reference implementation decodes to
    /// the names it was written from, and the token streams inside that frame
    /// are decoded by the rANS Nx16 codec.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_the_name_tokeniser_is_decoded() {
        let stored = crate::cram_tokeniser::SPEC_FRAME;
        let block = CramBlock {
            method: 8,
            content_type: 4,
            content_id: 1,
            raw_size: 89,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(stored, &block).as_deref(),
            Some(crate::cram_tokeniser::SPEC_NAMES),
            "the name tokeniser block is not decoded"
        );
    }

    /// A block whose data is compressed with the fqzcomp codec of CRAM 3.1
    /// comes back whole: the frame of the reference implementation decodes to
    /// the quality values it was written from.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_compressed_with_fqzcomp_is_decoded() {
        let stored = crate::cram_fqz::SPECIFICATION;
        let block = CramBlock {
            method: 7,
            content_type: 4,
            content_id: 1,
            raw_size: 20,
            data_at: 0,
            data_len: stored.len(),
            total_len: stored.len(),
            crc32: None,
        };
        assert_eq!(
            cram_block_bytes(stored, &block).as_deref(),
            Some(&b"IIIIIIIIIIIIIIIIIIII"[..]),
            "the fqzcomp block is not decoded"
        );
    }

    /// A block whose raw size is zero is empty whatever its method byte
    /// says (CRAMv3 §8), and an empty block is not an undecoded one.
    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_block_with_no_bytes_is_empty_whatever_its_method_says() {
        let block = CramBlock {
            method: 7,
            content_type: 4,
            content_id: 1,
            raw_size: 0,
            data_at: 0,
            data_len: 0,
            total_len: 0,
            crc32: None,
        };
        assert_eq!(cram_block_bytes(&[], &block).as_deref(), Some(&[][..]));
    }

    /// A CRAM map: the size in bytes, the number of keys, then the
    /// entries. The size counts the key count and the entries together.
    #[cfg(feature = "cram")]
    fn cram_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut body = itf8_put(entries.len() as i32);
        for (key, value) in entries {
            body.extend_from_slice(key);
            body.extend_from_slice(value);
        }
        let mut out = itf8_put(body.len() as i32);
        out.extend_from_slice(&body);
        out
    }

    /// An encoding: the codec id, the number of bytes of parameters, then
    /// the parameters themselves (CRAMv2.1 §3).
    #[cfg(feature = "cram")]
    fn cram_encoding(codec: i32, params: &[u8]) -> Vec<u8> {
        let mut out = itf8_put(codec);
        out.extend_from_slice(&itf8_put(params.len() as i32));
        out.extend_from_slice(params);
        out
    }

    /// The beta codec: the offset and the number of bits.
    #[cfg(feature = "cram")]
    fn cram_beta(offset: i32, bits: i32) -> Vec<u8> {
        let mut params = itf8_put(offset);
        params.extend_from_slice(&itf8_put(bits));
        cram_encoding(6, &params)
    }

    /// The external codec: the content id of the block the bytes are in.
    #[cfg(feature = "cram")]
    fn cram_external(block_id: i32) -> Vec<u8> {
        cram_encoding(1, &itf8_put(block_id))
    }

    /// A compression header block: the preservation map, the data series
    /// encoding map and the tag encoding map (CRAMv2.1 §7.4).
    #[cfg(feature = "cram")]
    fn cram_compression_header_block(series: &[(&[u8; 2], Vec<u8>)]) -> Vec<u8> {
        let mut out = cram_map(&[
            (b"RN".to_vec(), vec![0u8]),
            (b"AP".to_vec(), vec![0u8]),
            (b"RR".to_vec(), vec![0u8]),
            (b"SM".to_vec(), vec![0x1bu8; 5]),
            (b"TD".to_vec(), itf8_put(0)),
        ]);
        let encodings: Vec<(Vec<u8>, Vec<u8>)> = series
            .iter()
            .map(|(key, value)| (key.to_vec(), value.clone()))
            .collect();
        out.extend_from_slice(&cram_map(&encodings));
        out.extend_from_slice(&cram_map(&[]));
        out
    }

    /// A slice header block (CRAMv2.1 §7.5).
    #[cfg(feature = "cram")]
    fn cram_slice_header_block(reference_id: i32, records: i32, content_ids: &[i32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&itf8_put(reference_id));
        out.extend_from_slice(&itf8_put(-1)); // alignment start
        out.extend_from_slice(&itf8_put(0)); // alignment span
        out.extend_from_slice(&itf8_put(records));
        out.extend_from_slice(&ltf8_put(0)); // record counter
                                             // The number of blocks, and then the block content ids as an
                                             // array: an array's length comes first.
        out.extend_from_slice(&itf8_put(content_ids.len() as i32 + 1));
        out.extend_from_slice(&itf8_put(content_ids.len() as i32));
        for id in content_ids {
            out.extend_from_slice(&itf8_put(*id));
        }
        out.extend_from_slice(&itf8_put(-1)); // embedded reference bases
        out.extend_from_slice(&[0u8; 16]); // reference md5
        out
    }

    /// A container whose landmarks point at its slices: the byte offsets
    /// of the slices within the container's blocks region.
    #[cfg(feature = "cram")]
    fn cram_container_with_landmarks(
        major: u8,
        blocks: &[Vec<u8>],
        landmarks: &[usize],
        records: i32,
    ) -> Vec<u8> {
        let length: usize = blocks.iter().map(|b| b.len()).sum();
        let mut out = Vec::new();
        out.extend_from_slice(&(length as i32).to_le_bytes());
        out.extend_from_slice(&itf8_put(0)); // reference id
        out.extend_from_slice(&itf8_put(0)); // start
        out.extend_from_slice(&itf8_put(0)); // span
        out.extend_from_slice(&itf8_put(records));
        if major >= 3 {
            out.extend_from_slice(&ltf8_put(0)); // record counter
        } else {
            out.extend_from_slice(&itf8_put(0)); // record counter
        }
        out.extend_from_slice(&ltf8_put(0)); // bases
        out.extend_from_slice(&itf8_put(blocks.len() as i32));
        out.extend_from_slice(&itf8_put(landmarks.len() as i32));
        for lm in landmarks {
            out.extend_from_slice(&itf8_put(*lm as i32));
        }
        if major >= 3 {
            let sum = cram_crc32(&out);
            out.extend_from_slice(&sum);
        }
        for b in blocks {
            out.extend_from_slice(b);
        }
        out
    }

    /// A bit stream, most significant bit first (CRAMv2.1 §2.2).
    #[cfg(feature = "cram")]
    struct CramBitWriter {
        bits: Vec<u8>,
    }

    #[cfg(feature = "cram")]
    impl CramBitWriter {
        fn new() -> Self {
            CramBitWriter { bits: Vec::new() }
        }

        fn write(&mut self, value: u32, n: u32) {
            for i in (0..n).rev() {
                self.bits.push(((value >> i) & 1) as u8);
            }
        }

        fn to_bytes(&self) -> Vec<u8> {
            let mut out = Vec::new();
            for chunk in self.bits.chunks(8) {
                let mut byte = 0u8;
                for bit in chunk {
                    byte = (byte << 1) | bit;
                }
                out.push(byte << (8 - chunk.len()));
            }
            out
        }
    }

    /// Decode one value with a codec, from a bit stream.
    #[cfg(feature = "cram")]
    fn cram_decode_one(codec: &CramCodec, bits: &[u8]) -> Option<i64> {
        let mut decode = CramDecode {
            bits: CramBits::new(bits),
            externals: Vec::new(),
        };
        decode.read_int(codec)
    }

    /// The CRAM 2.1 specification's end-of-file container, byte for byte:
    /// the container header, then the compression header block, and no
    /// CRC32 anywhere -- CRAM 3 added those. The specification says the
    /// marker is exactly 30 bytes long, and the container header is 19 of
    /// them.
    ///
    /// The reference id is spelled `ff ff ff ff 0f` here, which is the form
    /// htsjdk writes for a v2 marker. The specification's own listing spells
    /// it as five `ff`s; both decode to -1, and the two constants below are
    /// the only difference between them.
    #[cfg(feature = "cram")]
    const CRAM_2_1_EOF: [u8; 30] = [
        0x0b, 0x00, 0x00, 0x00, // length: the size of the blocks
        0xff, 0xff, 0xff, 0xff, 0x0f, // reference id: -1
        0xe0, 0x45, 0x4f, 0x46, // start: 4542278 ("EOF")
        0x00, // alignment span
        0x00, // number of records
        0x00, // record counter
        0x00, // bases
        0x01, // number of blocks
        0x00, // landmarks: none
        0x00, 0x01, 0x00, 0x06, 0x06, // the compression header block's header
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, // the block's data
    ];

    /// The same marker as the CRAM 2.1 specification prints it: the
    /// reference id as five `ff`s (§8). The last byte of an ITF-8's 5-byte
    /// form is masked with `0x0f`, so this is the same -1.
    #[cfg(feature = "cram")]
    const CRAM_2_1_EOF_SPECIFICATION: [u8; 30] = [
        0x0b, 0x00, 0x00, 0x00, // length: the size of the blocks
        0xff, 0xff, 0xff, 0xff, 0xff, // reference id: -1
        0xe0, 0x45, 0x4f, 0x46, // start: 4542278 ("EOF")
        0x00, // alignment span
        0x00, // number of records
        0x00, // record counter
        0x00, // bases
        0x01, // number of blocks
        0x00, // landmarks: none
        0x00, 0x01, 0x00, 0x06, 0x06, // the compression header block's header
        0x01, 0x00, 0x01, 0x00, 0x01, 0x00, // the block's data
    ];

    #[test]
    #[cfg(feature = "cram")]
    fn a_real_cram_walks_its_containers_and_totals_the_alignments() {
        // The file htsjdk wrote: eight reads on chr1, in one data
        // container whose header states the count. htsjdk read the same
        // file back and printed the eight records, so eight is the number
        // this reader has to report -- and the walk has to reach the
        // second container to find it.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sample.cram");
        let data = std::fs::read(path).expect("the htsjdk fixture");
        let report = cram_report(&data);
        assert!(report.contains("cram 3.1"), "{report}");
        assert!(report.contains("file id: rgx-fixture"), "{report}");
        assert!(report.contains("@SQ\tSN:chr1\tLN:1000"), "{report}");
        assert!(report.contains("containers walked: 2"), "{report}");
        assert!(
            report.contains("alignments in those containers: 8"),
            "{report}"
        );
        assert!(
            !report.contains("note: the container walk stopped"),
            "the walk must reach the end of the file: {report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_2_1_container_is_read_the_way_its_specification_writes_it() {
        // The specification's own bytes: the container header, then the
        // compression header block. The header is 19 bytes and the blocks
        // are 11, which is the 30 the specification says the marker is
        // long; a reader that read the length as something else, or that
        // counted a CRC32 CRAM 2 does not have, would not add up.
        let mut f = cram_file_def_edition(2, 1, "eof.cram");
        f.extend_from_slice(&CRAM_2_1_EOF);
        let report = cram_report(&f);
        assert!(report.contains("cram 2.1"), "{report}");
        assert!(report.contains("length 11 byte(s) of blocks"), "{report}");
        assert!(report.contains("plus a 19 byte(s) header"), "{report}");
        assert!(
            report.contains("reference id -1, start 4542278"),
            "{report}"
        );
        assert!(report.contains("blocks: 1"), "{report}");
        assert!(
            report.contains("method raw, content type compression header"),
            "{report}"
        );
        assert!(report.contains("6 raw byte(s) declared"), "{report}");
        assert!(
            report.contains("this edition has no CRC32 to verify"),
            "{report}"
        );
        assert!(
            report.contains(
                "end-of-file marker: 30 byte(s), the reference id -1 spelled ff ff ff ff 0f"
            ),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn the_cram_2_1_end_of_file_marker_fixture_is_read() {
        // The corpus fixture: the 26-byte file definition and the 30-byte
        // end-of-file container, which is the specification's own bytes with
        // the reference id spelled the way htsjdk spells it.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/cram/cram21-eof.cram");
        let data = std::fs::read(path).expect("the CRAM 2.1 fixture");
        assert_eq!(
            data.len(),
            56,
            "the fixture is the file definition plus the marker"
        );
        let report = cram_report(&data);
        assert!(report.contains("cram 2.1"), "{report}");
        assert!(report.contains("file id: cram21-eof"), "{report}");
        assert!(
            report.contains("first container (the end-of-file marker)"),
            "{report}"
        );
        assert!(
            report.contains(
                "end-of-file marker: 30 byte(s), the reference id -1 spelled ff ff ff ff 0f"
            ),
            "{report}"
        );
        assert!(
            report.contains("crc32: this edition has no CRC32 to verify"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn the_specification_s_own_end_of_file_marker_is_recognised_as_its_bytes() {
        // The 30 bytes §8 prints, with the reference id as five `ff`s. The
        // marker is a literal byte string, so a file that carries exactly
        // those bytes can be said to carry the specification's own marker.
        let mut f = cram_file_def_edition(2, 1, "eof-spec.cram");
        f.extend_from_slice(&CRAM_2_1_EOF_SPECIFICATION);
        let report = cram_report(&f);
        assert!(
            report.contains("the reference id -1 spelled ff ff ff ff ff"),
            "{report}"
        );
        assert!(
            report.contains("the CRAM 2.1 specification's own byte string, §8"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn both_spellings_of_the_reference_id_minus_one_decode_to_minus_one() {
        // The CRAM 2.1 specification's end-of-file listing spells -1 as five
        // `ff`s and htsjdk writes `ff ff ff ff 0f`. Both are the same value,
        // because the last byte of an ITF-8's 5-byte form is masked with
        // `0x0f`; a reader that admits only one of them refuses a file the
        // specification itself describes.
        assert_eq!(itf8_get(&[0xff, 0xff, 0xff, 0xff, 0xff]), Some((-1, 5)));
        assert_eq!(itf8_get(&[0xff, 0xff, 0xff, 0xff, 0x0f]), Some((-1, 5)));
    }

    #[test]
    #[cfg(feature = "cram")]
    fn the_cram_codecs_decode_the_specifications_worked_examples() {
        // Beta coding (§12.2): the value in binary, in the number of bits
        // the codec says.
        let beta = CramCodec::Beta { offset: 0, bits: 3 };
        assert_eq!(cram_decode_one(&beta, &[0b1010_0000]), Some(5));
        let beta = CramCodec::Beta { offset: 2, bits: 3 };
        assert_eq!(cram_decode_one(&beta, &[0b1010_0000]), Some(3));

        // Gamma coding: 1 is "1", 2 is "010", 3 is "011", 4 is "00100".
        let gamma = CramCodec::Gamma { offset: 0 };
        assert_eq!(cram_decode_one(&gamma, &[0b1000_0000]), Some(1));
        assert_eq!(cram_decode_one(&gamma, &[0b0100_0000]), Some(2));
        assert_eq!(cram_decode_one(&gamma, &[0b0110_0000]), Some(3));
        assert_eq!(cram_decode_one(&gamma, &[0b0010_0000]), Some(4));

        // Subexponential coding with k = 2: 0 is "000", 1 is "001", 2 is
        // "010", 3 is "011", 4 is "1000", 5 is "1001".
        let subexp = CramCodec::Subexp { offset: 0, k: 2 };
        assert_eq!(cram_decode_one(&subexp, &[0b0000_0000]), Some(0));
        assert_eq!(cram_decode_one(&subexp, &[0b0010_0000]), Some(1));
        assert_eq!(cram_decode_one(&subexp, &[0b0100_0000]), Some(2));
        assert_eq!(cram_decode_one(&subexp, &[0b0110_0000]), Some(3));
        assert_eq!(cram_decode_one(&subexp, &[0b1000_0000]), Some(4));
        assert_eq!(cram_decode_one(&subexp, &[0b1001_0000]), Some(5));

        // Golomb coding with M = 10: 4 is "0100" and 42 is "11110010".
        let golomb = CramCodec::Golomb { offset: 0, m: 10 };
        assert_eq!(cram_decode_one(&golomb, &[0b0100_0000]), Some(4));
        assert_eq!(cram_decode_one(&golomb, &[0b1111_0010]), Some(42));

        // A canonical Huffman code: the alphabet is sorted by bit length
        // and then by value, and the first symbol takes an all-zero code.
        let huffman = CramCodec::Huffman {
            alphabet: vec![7, 9],
            lengths: vec![1, 2],
        };
        assert_eq!(cram_decode_one(&huffman, &[0b0000_0000]), Some(7));
        assert_eq!(cram_decode_one(&huffman, &[0b1000_0000]), Some(9));

        // An alphabet with a single value has no output bits at all.
        let huffman = CramCodec::Huffman {
            alphabet: vec![1],
            lengths: vec![0],
        };
        assert_eq!(cram_decode_one(&huffman, &[0b0000_0000]), Some(1));
    }

    #[test]
    #[cfg(feature = "cram")]
    fn the_compression_header_of_the_htsjdk_fixture_is_read_as_htsjdk_reads_it() {
        // The file htsjdk wrote: its compression header says which codec
        // each data series is written with, and htsjdk's own reader says
        // the same. Every one of the twenty-six data series is checked
        // here, and the tag's own encoding with them.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/sample.cram");
        let data = std::fs::read(path).expect("the htsjdk fixture");
        let report = cram_report(&data);
        assert!(report.contains("data series encodings: 26"), "{report}");
        assert!(
            report.contains("BF: external: the bytes are in external block 15"),
            "{report}"
        );
        assert!(
            report.contains("CF: external: the bytes are in external block 16"),
            "{report}"
        );
        assert!(
            report.contains("RI: external: the bytes are in external block 33"),
            "{report}"
        );
        assert!(
            report.contains("RL: external: the bytes are in external block 25"),
            "{report}"
        );
        assert!(
            report.contains("AP: external: the bytes are in external block 17"),
            "{report}"
        );
        assert!(
            report.contains("RG: external: the bytes are in external block 18"),
            "{report}"
        );
        assert!(
            report.contains("RN: byte array: terminated by 0x00, in external block 11"),
            "{report}"
        );
        assert!(
            report.contains("FN: external: the bytes are in external block 26"),
            "{report}"
        );
        assert!(
            report.contains("FP: external: the bytes are in external block 28"),
            "{report}"
        );
        assert!(
            report.contains("FC: external: the bytes are in external block 27"),
            "{report}"
        );
        assert!(
            report.contains("BA: external: the bytes are in external block 30"),
            "{report}"
        );
        assert!(
            report.contains("QS: external: the bytes are in external block 12"),
            "{report}"
        );
        assert!(
            report.contains("IN: byte array: terminated by 0x09, in external block 13"),
            "{report}"
        );
        assert!(
            report.contains("SC: byte array: terminated by 0x09, in external block 14"),
            "{report}"
        );
        assert!(report.contains("tag encodings: 1"), "{report}");
        assert!(
            report.contains("NMc: byte array: the length is encoded first"),
            "{report}"
        );
        // The preservation map: the read names are kept, the positions
        // are not delta encoded and a reference is needed.
        assert!(report.contains("read names preserved"), "{report}");
        assert!(
            report.contains("alignment positions not delta encoded"),
            "{report}"
        );
        assert!(report.contains("reference required"), "{report}");
        // The slice header: eight records on chr1 from position 100.
        assert!(
            report.contains(
                "slice: reference id 0, alignment start 100, alignment span 185, 8 record(s)"
            ),
            "{report}"
        );
        // The records themselves are decoded now: every block method
        // the file uses -- the rANS Nx16 codec, the name tokeniser, the
        // fqzcomp codec and gzip -- is one this reader carries.
        assert!(report.contains("records: 8"), "{report}");
        assert!(report.contains("name read0"), "{report}");
        // The bases are the one thing that stays out: they are
        // reconstructed from the reference, which this reader does not carry.
        assert!(
            report.contains("not decoded: the bases of a mapped read"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_2_1_slice_is_expanded_into_its_records() {
        // A CRAM 2.1 file with one slice and one unmapped read, built
        // byte by byte from the specification's tables: the compression
        // header block (the preservation map, the data series encoding
        // map and the tag encoding map), the slice header block, the core
        // data block (a bit stream) and the external block the bases are
        // in.
        let mut core = CramBitWriter::new();
        core.write(0x1c5, 16); // the BAM flags: unmapped, first and last
        core.write(0, 8); // the CRAM flags: no mate, no quality array
        core.write(5, 8); // the read length
        core.write(0, 8); // the alignment start
        core.write(1, 8); // the read group, with the codec's offset of 1
        core.write(0, 8); // the tag line: no tags
        let core = core.to_bytes();

        let compression = cram_compression_header_block(&[
            (b"BF", cram_beta(0, 16)),
            (b"CF", cram_beta(0, 8)),
            (b"RL", cram_beta(0, 8)),
            (b"AP", cram_beta(0, 8)),
            (b"RG", cram_beta(1, 8)),
            (b"TL", cram_beta(0, 8)),
            (b"BA", cram_external(1)),
        ]);
        let compression_block = cram_block_edition(2, 0, 1, 0, &compression);
        let landmark = compression_block.len();
        let slice_block = cram_block_edition(2, 0, 2, 0, &cram_slice_header_block(-1, 1, &[1]));
        let core_block = cram_block_edition(2, 0, 5, 0, &core);
        let bases_block = cram_block_edition(2, 0, 4, 1, b"ACGTA");

        let mut f = cram_file_def_edition(2, 1, "slice.cram");
        f.extend_from_slice(&cram_container_with_landmarks(
            2,
            &[compression_block, slice_block, core_block, bases_block],
            &[landmark],
            1,
        ));
        f.extend_from_slice(&CRAM_2_1_EOF);
        let report = cram_report(&f);
        assert!(report.contains("slices: 1"), "{report}");
        assert!(report.contains("records: 1"), "{report}");
        assert!(
            report.contains(
                "flags 0x1c5, cram flags 0x0, reference id -1, position 0, length 5, group 0"
            ),
            "{report}"
        );
        assert!(report.contains("bases ACGTA"), "{report}");
        // The slice header is the specification's: the reference id is
        // -1 for an unmapped slice.
        assert!(
            report.contains(
                "slice: reference id -1, alignment start -1, alignment span 0, 1 record(s)"
            ),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_2_file_walks_its_containers_too() {
        // The same walk in the edition before: the record counter is an
        // ITF-8 there and neither the container header nor the blocks
        // carry a CRC32.
        let header = "@HD\tVN:1.6\n";
        let mut f = cram_file_def_edition(2, 1, "v2.cram");
        f.extend_from_slice(&cram_container_edition(
            2,
            &[sam_header_block_edition(2, 0, header)],
            0,
        ));
        f.extend_from_slice(&cram_container_edition(
            2,
            &[cram_block_edition(2, 4, 4, 1, &[0u8; 32])],
            12,
        ));
        f.extend_from_slice(&CRAM_2_1_EOF);
        let report = cram_report(&f);
        assert!(report.contains("cram 2.1"), "{report}");
        assert!(report.contains("@HD\tVN:1.6"), "{report}");
        assert!(report.contains("containers walked: 2"), "{report}");
        assert!(
            report.contains("alignments in those containers: 12"),
            "{report}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_1_file_is_refused_by_name() {
        let mut f = cram_file_def_edition(1, 0, "old.cram");
        f.extend_from_slice(&[0u8; 32]);
        let err = describe_cram(&f).expect_err("must refuse CRAM 1");
        let msg = format!("{err}");
        assert!(msg.contains("CRAM 1.0 is refused"), "{msg}");
        assert!(
            msg.contains("no CRAM 1 specification is published"),
            "{msg}"
        );
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_4_file_is_refused_by_name() {
        let mut f = cram_file_def_edition(4, 0, "draft.cram");
        f.extend_from_slice(&[0u8; 32]);
        let err = describe_cram(&f).expect_err("must refuse CRAM 4");
        let msg = format!("{err}");
        assert!(msg.contains("CRAM 4.0 is refused"), "{msg}");
        assert!(msg.contains("draft"), "{msg}");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_container_with_two_blocks_reads_the_second_one() {
        // A block occupies its header, its data and its CRC32: a reader
        // that steps over the data alone lands inside the next block's
        // header, and the second block is then read wrong.
        let header = "@HD\tVN:1.6\n";
        let mut f = cram_file_def("two-blocks.cram");
        f.extend_from_slice(&cram_container(
            &[sam_header_block(0, header), cram_block(0, 4, 1, &[0u8; 20])],
            0,
        ));
        let report = cram_report(&f);
        assert!(report.contains("blocks: 2"), "{report}");
        assert!(
            report.contains("0: method raw, content type file header"),
            "{report}"
        );
        assert!(
            report.contains("1: method raw, content type external data"),
            "{report}"
        );
        assert!(report.contains("20 raw byte(s) declared"), "{report}");
    }

    #[test]
    #[cfg(feature = "cram")]
    fn a_cram_with_an_unparsable_header_container_bails_without_panicking() {
        // A container header whose landmark count is 0xff, the reserved
        // ITF-8 prefix: the walk must refuse rather than index with it.
        let mut f = cram_file_def("broken.cram");
        f.extend_from_slice(&64i32.to_le_bytes()); // length
        f.extend_from_slice(&itf8_put(0)); // reference id
        f.extend_from_slice(&itf8_put(0)); // start
        f.extend_from_slice(&itf8_put(0)); // span
        f.extend_from_slice(&itf8_put(0)); // records
        f.extend_from_slice(&ltf8_put(0)); // record counter
        f.extend_from_slice(&ltf8_put(0)); // bases
        f.push(0x00); // blocks
        f.push(0xff); // landmarks: reserved prefix
        let err = describe_cram(&f).expect_err("must bail");
        assert!(format!("{err}").contains("cram:"), "{err}");

        // And one whose header runs off the end of the file entirely.
        let mut g = cram_file_def("short.cram");
        g.extend_from_slice(&1_000_000i32.to_le_bytes());
        g.push(0x00);
        assert!(describe_cram(&g).is_err());
    }
}
