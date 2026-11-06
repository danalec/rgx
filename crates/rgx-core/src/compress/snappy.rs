// SPDX-License-Identifier: Apache-2.0

//! Snappy — Google's LZ77-based compressor, decoding only.
//!
//! Written from the published format description: a stream is a varint
//! preamble carrying the length of the plaintext, then a sequence of
//! elements. Each element begins with a tag byte whose low two bits say
//! what it is — `00` a literal, `01` a copy with an 11-bit offset, `10` a
//! copy with a 16-bit offset, `11` a copy with a 32-bit offset — and whose
//! upper six bits carry a length, either inline or, for a literal of 60
//! bytes or more, in the 1..4 bytes that follow the tag.
//!
//! Three properties of the format are worth naming because each one is a way
//! to write a decoder that passes the easy cases and fails on real data:
//!
//! - **The offset is measured back from the write position**, not from the
//!   start of the output. Reading it as an absolute index yields a stream
//!   that decodes to the right *length* and the wrong *bytes*.
//! - **A copy may overlap what it is producing.** That is the run-length
//!   case — one byte then a copy of offset 1 — and a decoder that copies
//!   with `extend_from_slice` from a slice of its own output produces a
//!   short result instead of a repeated pattern.
//! - **The preamble is a claim, not a bound.** Nothing stops a stream
//!   declaring four gigabytes and then emitting two; the claim is checked
//!   against what the elements produced, and the ceiling is debited as
//!   bytes are emitted, never from the declared length.
//!
//! LevelDB and RocksDB compress their blocks with Snappy, which is the
//! reason this is here: without it their `.ldb` and `.sst` files are
//! compressed noise to a search tool.

use super::cap::{Bounded, OutputCap, UNLIMITED};
use super::error::{CompressError, CompressResult};
use alloc::vec::Vec;

/// The most the output buffer is preallocated from the declared length.
///
/// The declaration is attacker-controlled text: honouring it outright is how
/// a two-byte stream asks for four gigabytes before the first element has
/// been read. The real length arrives as bytes are emitted, so the buffer
/// grows on its own from this modest start.
const MAX_PREALLOC: usize = 64 * 1024;

/// Snappy decoder.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnappyDecoder {
    _priv: (),
}

impl SnappyDecoder {
    /// Create a decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { _priv: () }
    }

    /// Decode one stream under an unlimited cap.
    pub fn decode(&self, data: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_bounded(data, UNLIMITED).map(|b| b.bytes)
    }

    /// Decode one stream, stopping at `limit` emitted bytes.
    ///
    /// A stream that declares more than `limit` is not refused from its
    /// header the way a framed format can be: Snappy's declaration is the
    /// output length and the elements are the only thing that fills it, so
    /// the decode runs and is stopped by the cap as bytes leave.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> CompressResult<Bounded> {
        let mut cap = OutputCap::new(limit);
        self.decompress(data, &mut cap)
    }

    /// The decode itself, with a caller-supplied cap so a container can
    /// spend one budget across several blocks.
    pub fn decompress(&self, data: &[u8], cap: &mut OutputCap) -> CompressResult<Bounded> {
        let limit = cap.limit();
        let mut p = 0usize;
        let declared = read_varint(data, &mut p).ok_or(CompressError::UnexpectedEof)?;
        let prealloc = declared.min(MAX_PREALLOC as u64) as usize;
        let mut out: Vec<u8> = Vec::with_capacity(prealloc);

        while p < data.len() {
            let tag = data[p];
            p += 1;
            match tag & 3 {
                0 => {
                    let n = literal_len(tag, data, &mut p)?;
                    let end = p.checked_add(n).ok_or(CompressError::UnexpectedEof)?;
                    let bytes = data.get(p..end).ok_or(CompressError::UnexpectedEof)?;
                    p = end;
                    if !cap.take(n as u64) {
                        return Ok(Bounded::stopped(out, Some(declared), limit));
                    }
                    out.extend_from_slice(bytes);
                }
                1 => {
                    let byte = *data.get(p).ok_or(CompressError::UnexpectedEof)?;
                    p += 1;
                    let len = 4 + usize::from((tag >> 2) & 7);
                    let off = (usize::from(tag >> 5) << 8) | usize::from(byte);
                    if !emit_copy(&mut out, off, len, cap)? {
                        return Ok(Bounded::stopped(out, Some(declared), limit));
                    }
                }
                2 => {
                    let len = usize::from(tag >> 2) + 1;
                    let off = le(data, &mut p, 2)?;
                    if !emit_copy(&mut out, off, len, cap)? {
                        return Ok(Bounded::stopped(out, Some(declared), limit));
                    }
                }
                _ => {
                    let len = usize::from(tag >> 2) + 1;
                    let off = le(data, &mut p, 4)?;
                    if !emit_copy(&mut out, off, len, cap)? {
                        return Ok(Bounded::stopped(out, Some(declared), limit));
                    }
                }
            }
        }

        if out.len() as u64 != declared {
            return Err(CompressError::CorruptedData(
                "elements produced a different length than the preamble declared",
            ));
        }
        Ok(Bounded::complete(out, Some(declared), limit))
    }
}

/// The length a literal tag names, and the cursor past its length field.
///
/// A tag of 60..63 does not carry the length inline; the low three bits of
/// that value are how many bytes follow it.
fn literal_len(tag: u8, data: &[u8], p: &mut usize) -> CompressResult<usize> {
    let n = usize::from(tag >> 2);
    if n < 60 {
        return Ok(n + 1);
    }
    let extra = n - 59;
    Ok(le(data, p, extra)? + 1)
}

/// `n` little-endian bytes at the cursor as a `usize`.
fn le(data: &[u8], p: &mut usize, n: usize) -> CompressResult<usize> {
    let end = p.checked_add(n).ok_or(CompressError::UnexpectedEof)?;
    let bytes = data.get(*p..end).ok_or(CompressError::UnexpectedEof)?;
    let mut v = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        v |= usize::from(b) << (8 * i);
    }
    *p = end;
    Ok(v)
}

/// The preamble: the plaintext length, seven bits per byte, low group first.
fn read_varint(data: &[u8], p: &mut usize) -> Option<u64> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    while let Some(&b) = data.get(*p) {
        *p += 1;
        // A group that would start beyond the width of a u64 is a stream
        // announcing a length nothing could hold.
        if shift >= 64 {
            return None;
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
    }
    None
}

/// One back-reference. `Ok(false)` means the cap stopped the decode.
///
/// The copy is applied a byte at a time because the ranges overlap by
/// design: an offset of 1 with a length of 60 is a run, and it reads bytes
/// this copy is still producing. Copying the source range in one go would
/// borrow the output immutably while extending it and could only copy the
/// bytes that existed when the copy began.
fn emit_copy(
    out: &mut Vec<u8>,
    off: usize,
    len: usize,
    cap: &mut OutputCap,
) -> CompressResult<bool> {
    // Offsets run back from the write position, so an offset past what has
    // been produced -- and zero, which would point at the byte being written
    // -- is a stream referencing bytes that are not there. That is
    // corruption, not a ceiling: reporting it as a cap would hand the
    // caller a short payload that reads like a whole one.
    if off == 0 || off > out.len() {
        return Err(CompressError::CorruptedData(
            "copy reaches before the start of the output",
        ));
    }
    if !cap.take(len as u64) {
        return Ok(false);
    }
    let start = out.len() - off;
    for i in 0..len {
        let byte = out[start + i];
        out.push(byte);
    }
    Ok(true)
}

#[cfg(all(test, feature = "snappy"))]
mod tests {
    //! Decoding against streams a working encoder produced.
    //!
    //! Two tiers of evidence, and the second exists because the first is
    //! not enough: every `.bin` here came out of python-snappy, but a real
    //! encoder never emits three of the six element forms — its window is too
    //! small to need a 4-byte offset, and it has no reason to spell a length
    //! in three or four bytes. A decoder can therefore pass the whole
    //! reference corpus with those branches dead. The ones it does not reach
    //! are built from the format description and then checked against the
    //! reference *decoder*, so they are streams Snappy itself accepts rather
    //! than a restatement of how this file reads the specification.

    use super::*;

    /// Every fixture pair. The `.bin` is the stream, the `.expected` the
    /// plaintext it must produce.
    fn fixtures() -> Vec<(&'static str, &'static [u8], &'static [u8])> {
        vec![
            (
                "empty",
                include_bytes!("../../testdata/snappy_empty.bin"),
                include_bytes!("../../testdata/snappy_empty.expected"),
            ),
            (
                "lit",
                include_bytes!("../../testdata/snappy_lit.bin"),
                include_bytes!("../../testdata/snappy_lit.expected"),
            ),
            (
                "short",
                include_bytes!("../../testdata/snappy_short.bin"),
                include_bytes!("../../testdata/snappy_short.expected"),
            ),
            (
                "repeat",
                include_bytes!("../../testdata/snappy_repeat.bin"),
                include_bytes!("../../testdata/snappy_repeat.expected"),
            ),
            (
                "two_lines",
                include_bytes!("../../testdata/snappy_two_lines.bin"),
                include_bytes!("../../testdata/snappy_two_lines.expected"),
            ),
            (
                "json",
                include_bytes!("../../testdata/snappy_json.bin"),
                include_bytes!("../../testdata/snappy_json.expected"),
            ),
            (
                "len59",
                include_bytes!("../../testdata/snappy_len59.bin"),
                include_bytes!("../../testdata/snappy_len59.expected"),
            ),
            (
                "len60",
                include_bytes!("../../testdata/snappy_len60.bin"),
                include_bytes!("../../testdata/snappy_len60.expected"),
            ),
            (
                "len61",
                include_bytes!("../../testdata/snappy_len61.bin"),
                include_bytes!("../../testdata/snappy_len61.expected"),
            ),
            (
                "len62",
                include_bytes!("../../testdata/snappy_len62.bin"),
                include_bytes!("../../testdata/snappy_len62.expected"),
            ),
            (
                "len63",
                include_bytes!("../../testdata/snappy_len63.bin"),
                include_bytes!("../../testdata/snappy_len63.expected"),
            ),
            (
                "len64",
                include_bytes!("../../testdata/snappy_len64.bin"),
                include_bytes!("../../testdata/snappy_len64.expected"),
            ),
            (
                "len65",
                include_bytes!("../../testdata/snappy_len65.bin"),
                include_bytes!("../../testdata/snappy_len65.expected"),
            ),
            (
                "len255",
                include_bytes!("../../testdata/snappy_len255.bin"),
                include_bytes!("../../testdata/snappy_len255.expected"),
            ),
            (
                "len256",
                include_bytes!("../../testdata/snappy_len256.bin"),
                include_bytes!("../../testdata/snappy_len256.expected"),
            ),
            (
                "len300",
                include_bytes!("../../testdata/snappy_len300.bin"),
                include_bytes!("../../testdata/snappy_len300.expected"),
            ),
            (
                "incompressible",
                include_bytes!("../../testdata/snappy_incompressible.bin"),
                include_bytes!("../../testdata/snappy_incompressible.expected"),
            ),
            (
                "long_run",
                include_bytes!("../../testdata/snappy_long_run.bin"),
                include_bytes!("../../testdata/snappy_long_run.expected"),
            ),
            (
                "block",
                include_bytes!("../../testdata/snappy_block.bin"),
                include_bytes!("../../testdata/snappy_block.expected"),
            ),
            (
                "copy4_far",
                include_bytes!("../../testdata/snappy_copy4_far.bin"),
                include_bytes!("../../testdata/snappy_copy4_far.expected"),
            ),
            (
                "lit_ext24",
                include_bytes!("../../testdata/snappy_lit_ext24.bin"),
                include_bytes!("../../testdata/snappy_lit_ext24.expected"),
            ),
            (
                "copy1_max",
                include_bytes!("../../testdata/snappy_copy1_max.bin"),
                include_bytes!("../../testdata/snappy_copy1_max.expected"),
            ),
            (
                "copy2_boundary",
                include_bytes!("../../testdata/snappy_copy2_boundary.bin"),
                include_bytes!("../../testdata/snappy_copy2_boundary.expected"),
            ),
            (
                "overlap",
                include_bytes!("../../testdata/snappy_overlap.bin"),
                include_bytes!("../../testdata/snappy_overlap.expected"),
            ),
        ]
    }

    #[test]
    fn every_fixture_decodes_to_its_plaintext() {
        let mut bytes = 0usize;
        for (name, compressed, expected) in fixtures() {
            let got = SnappyDecoder::new()
                .decode(compressed)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(got.len(), expected.len(), "{name}: length");
            assert_eq!(got.as_slice(), expected, "{name}: bytes");
            bytes += expected.len();
        }
        // A corpus that shrank to a handful of small cases would still pass
        // every assertion above.
        assert!(bytes > 250_000, "corpus is only {bytes} bytes of plaintext");
    }

    /// How the corpus divides across the six element forms.
    #[derive(Default)]
    struct Coverage {
        literal_inline: usize,
        literal_ext: [usize; 4],
        copy: [usize; 3],
    }

    /// Walk a stream's tags without decoding, to report which forms the
    /// fixtures reach.
    fn coverage(compressed: &[u8]) -> Coverage {
        let mut c = Coverage::default();
        let mut p = 0usize;
        read_varint(compressed, &mut p).expect("preamble");
        while p < compressed.len() {
            let tag = compressed[p];
            p += 1;
            match tag & 3 {
                0 => {
                    let n = usize::from(tag >> 2);
                    if n < 60 {
                        c.literal_inline += 1;
                        p += n + 1;
                    } else {
                        let extra = n - 59;
                        c.literal_ext[extra - 1] += 1;
                        let len = le(compressed, &mut p, extra).expect("length") + 1;
                        p += len;
                    }
                }
                1 => {
                    c.copy[0] += 1;
                    // The length is the three bits above the tag's low two,
                    // inline; only the offset byte follows.
                    p += 1;
                }
                2 => {
                    c.copy[1] += 1;
                    let _ = le(compressed, &mut p, 2).expect("offset");
                }
                _ => {
                    c.copy[2] += 1;
                    let _ = le(compressed, &mut p, 4).expect("offset");
                }
            }
        }
        c
    }

    /// The corpus must reach every form the format defines, with one
    /// exception stated rather than hidden: a *valid* four-byte literal
    /// length extension needs a literal of 16 MiB or more, which is not a
    /// fixture worth checking in. The arithmetic that reaches it —
    /// `n - 59` giving four bytes to read — is the same line the one-,
    /// two- and three-byte forms below it exercise, so what is untested is
    /// the size of the fixture, not a separate branch.
    #[test]
    fn the_corpus_reaches_every_element_form() {
        let mut total = Coverage::default();
        for (_, compressed, _) in fixtures() {
            let c = coverage(compressed);
            total.literal_inline += c.literal_inline;
            for i in 0..4 {
                total.literal_ext[i] += c.literal_ext[i];
            }
            for i in 0..3 {
                total.copy[i] += c.copy[i];
            }
        }
        assert!(total.literal_inline > 0, "no inline literals");
        for (i, n) in total.literal_ext.iter().enumerate().take(3) {
            assert!(
                *n > 0,
                "literal length extension of {} bytes untested",
                i + 1
            );
        }
        for (i, n) in total.copy.iter().enumerate() {
            assert!(*n > 0, "copy with a {}-byte offset untested", i + 1);
        }
    }

    /// A run is the case a decoder that copies in one go gets wrong: the
    /// bytes it reads are the ones it is still writing.
    #[test]
    fn an_overlapping_copy_repeats_what_it_is_producing() {
        let got = SnappyDecoder::new()
            .decode(include_bytes!("../../testdata/snappy_overlap.bin"))
            .expect("decode");
        assert_eq!(&got[..4], b"rgx-");
        assert_eq!(got.len(), 64);
        for chunk in got[4..].chunks(4) {
            assert_eq!(chunk, b"rgx-", "the run must stay uniform");
        }
    }

    #[test]
    fn the_ceiling_stops_the_decode_and_says_so() {
        let full = SnappyDecoder::new()
            .decode(include_bytes!("../../testdata/snappy_long_run.bin"))
            .expect("whole");
        let b = SnappyDecoder::new()
            .decode_bounded(include_bytes!("../../testdata/snappy_long_run.bin"), 1000)
            .expect("bounded");
        assert!(b.capped, "the ceiling must be reported, not hidden");
        assert!(b.capped || b.bytes.len() == full.len());
        assert!(b.bytes.len() <= 1000, "emitted {} bytes", b.bytes.len());
        assert_eq!(
            &b.bytes[..],
            &full[..b.bytes.len()],
            "a prefix, not a scramble"
        );
    }

    /// The declaration is a claim in five bytes of input. Believing it is how
    /// a bomb gets built, so the claim is echoed rather than adopted, and the
    /// ceiling is what bounds the work.
    #[test]
    fn a_huge_declaration_costs_nothing_and_the_ceiling_stops_the_elements() {
        // Declares 4 GiB, then delivers three 50-byte literals. The length is a
        // 7-bit group per byte: 2^32 is the fifth group carrying sixteen.
        let mut stream = vec![0x80, 0x80, 0x80, 0x80, 0x10];
        for _ in 0..3 {
            stream.push((50u8 - 1) << 2);
            stream.extend(core::iter::repeat_n(b'x', 50));
        }

        let b = SnappyDecoder::new()
            .decode_bounded(&stream, 60)
            .expect("a cap stops this, it does not fail it");
        assert!(b.capped, "the ceiling must be reported");
        // A literal is taken whole or not at all: the second one does not
        // fit in the ten bytes the ceiling has left, so the first stands
        // alone rather than being cut in half.
        assert_eq!(
            b.bytes.len(),
            50,
            "the prefix is a whole number of literals"
        );
        assert_eq!(&b.bytes[..5], b"xxxxx");
        assert_eq!(
            b.declared,
            Some(4 << 30),
            "the claim is echoed, not adopted"
        );
    }

    #[test]
    fn a_declaration_the_elements_do_not_meet_is_refused() {
        // Says 9, delivers 4.
        let stream = [9u8, (4u8 - 1) << 2, b'a', b'b', b'c', b'd'];
        match SnappyDecoder::new().decode(&stream) {
            Err(CompressError::CorruptedData(_)) => {}
            other => panic!("expected corruption, got {other:?}"),
        }
    }

    #[test]
    fn a_copy_that_reaches_before_the_start_is_corruption_not_a_ceiling() {
        // One literal 'a', then a 2-byte-offset copy of offset 4 with
        // nothing behind it.
        let mut stream = vec![2u8, 0x00, b'a', ((3u8 - 1) << 2) | 2];
        stream.extend_from_slice(&4u16.to_le_bytes());
        match SnappyDecoder::new().decode(&stream) {
            Err(CompressError::CorruptedData(_)) => {}
            other => panic!("expected corruption, got {other:?}"),
        }
    }

    #[test]
    fn a_copy_of_offset_zero_is_refused() {
        let mut stream = vec![5u8, 0x00, b'a', ((3u8 - 1) << 2) | 2];
        stream.extend_from_slice(&0u16.to_le_bytes());
        assert!(SnappyDecoder::new().decode(&stream).is_err());
    }

    #[test]
    fn a_truncated_element_is_refused() {
        // A literal of ten bytes with four of them present.
        let stream = [10u8, (9u8 << 2), b'a', b'b', b'c', b'd'];
        assert!(SnappyDecoder::new().decode(&stream).is_err());
    }

    #[test]
    fn an_empty_input_is_refused_rather_than_read_as_empty_output() {
        assert!(SnappyDecoder::new().decode(&[]).is_err());
    }

    #[test]
    fn a_preamble_that_overflows_is_refused() {
        // Eleven continuation bytes: the length is longer than a u64.
        let stream = [0xffu8; 12];
        assert!(SnappyDecoder::new().decode(&stream).is_err());
    }

    mod fuzz {
        use super::*;

        #[test]
        fn never_panics_on_arbitrary_bytes() {
            let mut corpus: Vec<(&str, Vec<u8>)> = fixtures()
                .into_iter()
                .map(|(name, compressed, _)| (name, compressed.to_vec()))
                .collect();
            // Plaintext as a seed too: a stream built from it is the shape
            // that survives mutation into something structurally valid.
            corpus.push(("repeated", b"rgx-".repeat(2000)));
            corpus.push(("empty", Vec::new()));
            crate::fuzzkit::assert_never_panics(corpus, 2000, "snappy", |data| {
                let d = SnappyDecoder::new();
                let _ = d.decode(data);
                let _ = d.decode_bounded(data, 1024);
            });
        }
    }
}
