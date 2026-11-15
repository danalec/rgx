// SPDX-License-Identifier: Apache-2.0

//! BOM sniffing and the UTF-16 decode the reference searcher does *before* it
//! looks for a line terminator.
//!
//! **Why this is a line-model question and not a transcoding nicety.**
//! `grep-searcher` sniffs a byte-order mark at the head of a buffer and, when
//! it finds one, searches the DECODED bytes: a UTF-16LE file is read as UTF-8,
//! so its line terminator is a real `\n` and every line is the text a person
//! wrote. Searching the raw bytes instead gives a different line model on the
//! same file, and the difference is not a detail -- in UTF-16LE the newline is
//! a `0a` followed by `00`, so a raw split ends each line at the `0a`, leaves
//! the `00` at the head of the next one, puts the BOM on the first line, and
//! leaves a one-byte `00` line after the final newline. A literal then matches
//! nothing at all, because no two letters are adjacent any more.
//!
//! It is invisible while non-ASCII input is routed away, and fatal the moment
//! it is not. Ripgrep's own behaviour, which is the target, lives in
//! `encoding_rs` and is reproduced here without the dependency.
//!
//! **What is and is not handled.** A UTF-8 BOM is stripped; UTF-16LE and
//! UTF-16BE are decoded. A UTF-16LE file with no BOM is *not* decoded -- the
//! reference does not, so a `0a` inside one is data rather than a terminator.
//!
//! **Why this module is public.** The mark decides what bytes are the text, so
//! every decision made *about* those bytes has to be made after it and not
//! before. The binary NUL heuristic is such a decision, and rgx's binary runs
//! it in a head sniff that happens outside the searcher -- so the caller needs
//! the same predicate and the same decode, or it reasons about a different
//! stream than the one the matcher sees. [`sniff`] and [`decode`] are that
//! shared surface; a second, private copy of the mark bytes in the binary is
//! how the two drifted apart in the first place.

use alloc::vec::Vec;
use core::cmp;
use core::fmt;

/// A byte-order mark the reference searcher acts on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bom {
    /// `ef bb bf`: stripped, the rest is already UTF-8.
    Utf8,
    /// `ff fe`: decoded to UTF-8.
    Utf16Le,
    /// `fe ff`: decoded to UTF-8.
    Utf16Be,
}

impl Bom {
    /// The mark's own length in bytes.
    // Never zero for any variant, so an `is_empty` would be constant `false`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            Bom::Utf8 => 3,
            Bom::Utf16Le | Bom::Utf16Be => 2,
        }
    }
}

/// The mark `bytes` opens with, or `None` when the reference would search these
/// bytes as they stand.
///
/// `ff fe 00 00` is UTF-16LE, not UTF-32: the reference's mark table has no
/// UTF-32 entry, so it decodes such a file as UTF-16 and the result is the
/// NUL-interleaved text a UTF-16LE read of UTF-32 data gives. A file in the
/// registry that is genuinely UTF-32LE is searched that way, so this is.
pub fn sniff(bytes: &[u8]) -> Option<Bom> {
    let &[b0, b1, ..] = bytes else {
        return None;
    };
    if b0 == 0xef {
        if b1 == 0xbb && bytes.get(2) == Some(&0xbf) {
            return Some(Bom::Utf8);
        }
    } else if b0 == 0xfe && b1 == 0xff {
        return Some(Bom::Utf16Be);
    } else if b0 == 0xff && b1 == 0xfe {
        return Some(Bom::Utf16Le);
    }
    None
}

/// Turns a raw byte stream into the bytes the searcher actually searches.
///
/// A stream with no mark is passed through untouched and read straight into the
/// caller's buffer, so nothing is allocated and nothing is copied on the path
/// every file but a handful takes.
pub struct Transcoder {
    /// The first bytes of the stream, held only until the mark is decided.
    head: [u8; 4],
    nhead: usize,
    bom: Option<Bom>,
    /// Whether `bom` is final: enough bytes seen, or the source ended.
    decided: bool,
    utf16: Utf16,
    /// Decoded bytes not yet handed to the caller.
    out: Vec<u8>,
    at: usize,
    scratch: Vec<u8>,
    eof: bool,
}

impl Default for Transcoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcoder {
    /// How much of a UTF-16 stream is read at a time.
    const CHUNK: usize = 64 * 1024;

    pub fn new() -> Self {
        Self {
            head: [0; 4],
            nhead: 0,
            bom: None,
            decided: false,
            utf16: Utf16::new(true),
            out: Vec::new(),
            at: 0,
            scratch: Vec::new(),
            eof: false,
        }
    }

    /// A stream the caller has already labelled (rgx's `-E`): decode with
    /// `bom` from the first byte, mark or no mark.
    ///
    /// A mark is DATA here -- the declaration is what is honoured, not a
    /// guess at the front -- which is [`force_decode`]'s rule over a stream
    /// instead of a buffer. `Bom::Utf8` is a pass-through, so a forced
    /// UTF-8 stream costs a short read and nothing else.
    pub fn forced(bom: Bom) -> Self {
        Self {
            head: [0; 4],
            nhead: 0,
            bom: Some(bom),
            decided: true,
            utf16: Utf16::new(bom != Bom::Utf16Be),
            out: Vec::new(),
            at: 0,
            scratch: Vec::new(),
            eof: false,
        }
    }

    /// Hand decoded bytes to `dst`, pulling from `src` as needed. `0` means the
    /// source is exhausted.
    ///
    /// `src` is handed whatever room is left in `dst` on the pass-through path,
    /// so an unmarked stream costs a short read and nothing else.
    pub fn read<R>(&mut self, dst: &mut [u8], src: &mut R) -> Result<usize, fmt::Error>
    where
        R: FnMut(&mut [u8]) -> Result<usize, fmt::Error>,
    {
        loop {
            if self.at < self.out.len() {
                let n = cmp::min(dst.len(), self.out.len() - self.at);
                dst[..n].copy_from_slice(&self.out[self.at..self.at + n]);
                self.at += n;
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            if !self.decided {
                self.decide(src)?;
                continue;
            }
            // Nothing decoded and nothing pending: only a stream that has to
            // move can read straight into the caller's buffer.
            if self.out.is_empty() && !self.is_utf16() {
                return src(dst);
            }
            self.decode(src)?;
        }
    }

    fn is_utf16(&self) -> bool {
        matches!(self.bom, Some(Bom::Utf16Le) | Some(Bom::Utf16Be))
    }

    /// Read up to four bytes -- enough to tell every mark apart -- and turn
    /// them into the first of the decoded stream.
    fn decide<R>(&mut self, src: &mut R) -> Result<(), fmt::Error>
    where
        R: FnMut(&mut [u8]) -> Result<usize, fmt::Error>,
    {
        while self.nhead < 4 {
            let n = src(&mut self.head[self.nhead..self.nhead + 1])?;
            if n == 0 {
                self.eof = true;
                break;
            }
            self.nhead += 1;
        }
        let head = &self.head[..self.nhead];
        self.bom = sniff(head);
        self.utf16 = Utf16::new(self.bom != Some(Bom::Utf16Be));
        self.decided = true;
        self.out.clear();
        self.at = 0;
        let bom = match self.bom {
            Some(bom) => bom,
            None => {
                self.out.extend_from_slice(head);
                self.nhead = 0;
                return Ok(());
            }
        };
        let body = &head[bom.len()..];
        if self.is_utf16() {
            self.utf16.push(body, &mut self.out);
        } else {
            self.out.extend_from_slice(body);
        }
        self.nhead = 0;
        Ok(())
    }

    /// Pull a chunk and decode it into `out`.
    fn decode<R>(&mut self, src: &mut R) -> Result<(), fmt::Error>
    where
        R: FnMut(&mut [u8]) -> Result<usize, fmt::Error>,
    {
        self.out.clear();
        self.at = 0;
        if self.scratch.len() < Self::CHUNK {
            self.scratch.resize(Self::CHUNK, 0);
        }
        let n = src(&mut self.scratch)?;
        if n == 0 {
            self.eof = true;
            if self.is_utf16() {
                // A code unit the stream ended in the middle of, and a
                // surrogate left without its other half, are both replacement
                // characters.
                self.utf16.finish(&mut self.out);
            }
            return Ok(());
        }
        if self.is_utf16() {
            self.utf16.push(&self.scratch[..n], &mut self.out);
        } else {
            self.out.extend_from_slice(&self.scratch[..n]);
        }
        Ok(())
    }
}

/// UTF-16 to UTF-8, carried across chunk boundaries.
///
/// Two things have to survive a read: a surrogate pair split between two
/// chunks, and a code unit whose first byte ended the previous one.
struct Utf16 {
    le: bool,
    high: Option<u16>,
    odd: Option<u8>,
}

impl Utf16 {
    fn new(le: bool) -> Self {
        Self {
            le,
            high: None,
            odd: None,
        }
    }

    /// Decode `bytes`, appending UTF-8 to `out`.
    fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        let mut i = 0;
        if let Some(lo) = self.odd.take() {
            if let Some(&hi) = bytes.first() {
                let unit = self.unit(&[lo, hi]);
                i = 1;
                self.emit(unit, out);
            } else {
                self.odd = Some(lo);
            }
        }
        while i + 1 < bytes.len() {
            let unit = self.unit(&bytes[i..i + 2]);
            i += 2;
            self.emit(unit, out);
        }
        if i < bytes.len() {
            self.odd = Some(bytes[i]);
        }
    }

    /// Emit whatever is still held, at end of input.
    fn finish(&mut self, out: &mut Vec<u8>) {
        if self.odd.take().is_some() {
            out.extend_from_slice(&REPLACEMENT);
        }
        if self.high.take().is_some() {
            out.extend_from_slice(&REPLACEMENT);
        }
    }

    #[inline]
    fn unit(&self, b: &[u8]) -> u16 {
        if self.le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    }

    fn emit(&mut self, unit: u16, out: &mut Vec<u8>) {
        if let Some(high) = self.high.take() {
            if (0xdc00..=0xdfff).contains(&unit) {
                let cp = 0x10000 + (((high as u32) - 0xd800) << 10) + ((unit as u32) - 0xdc00);
                encode(cp, out);
                return;
            }
            // A high surrogate followed by anything else: the high one stands
            // alone, and this unit is still to be dealt with.
            out.extend_from_slice(&REPLACEMENT);
        }
        if (0xd800..=0xdbff).contains(&unit) {
            self.high = Some(unit);
        } else if (0xdc00..=0xdfff).contains(&unit) {
            out.extend_from_slice(&REPLACEMENT);
        } else {
            encode(unit as u32, out);
        }
    }
}

const REPLACEMENT: [u8; 3] = [0xef, 0xbf, 0xbd];

/// Append the UTF-8 of one codepoint. `cp` is never a surrogate by the time it
/// gets here.
fn encode(cp: u32, out: &mut Vec<u8>) {
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push(0xc0 | (cp >> 6) as u8);
        out.push(0x80 | (cp & 0x3f) as u8);
    } else if cp < 0x10000 {
        out.push(0xe0 | (cp >> 12) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3f) as u8);
        out.push(0x80 | (cp & 0x3f) as u8);
    } else {
        out.push(0xf0 | (cp >> 18) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3f) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3f) as u8);
        out.push(0x80 | (cp & 0x3f) as u8);
    }
}

/// Strip a UTF-8/UTF-16 BOM from the front of `bytes` and return the
/// remainder as a borrowed slice. Callers that need to look at the
/// post-BOM bytes (a binary-detection memchr, a quick peek) can do so
/// without copying the buffer into a fresh `Vec<u8>`.
pub fn strip_bom(bom: Bom, bytes: &[u8]) -> &[u8] {
    &bytes[bom.len()..]
}

/// Decode a whole buffer, which is what a caller with every byte in hand needs:
/// nothing has to be carried across a boundary.
pub fn decode(bom: Bom, bytes: &[u8]) -> Vec<u8> {
    if bom == Bom::Utf8 {
        return bytes[bom.len()..].to_vec();
    }
    decode_utf16(bom == Bom::Utf16Be, &bytes[bom.len()..])
}

/// Decode UTF-16 bytes into UTF-8, with no byte-order-mark handling at all.
///
/// **Why this is separate from [`decode`].** A mark is not a character, and
/// whether the bytes start with one depends on what the bytes are: a file
/// opens with a mark and the mark is a preamble to strip, while a charset
/// *declaration* of `utf-16` is a statement about the byte order and the
/// mark may or may not be there. A decoder that always stripped two bytes
/// would eat the first character of a mark-less stream.
///
/// `be` says which order the units are in; the caller has decided that, and
/// this only carries it out.
pub fn decode_utf16(be: bool, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut d = Utf16::new(!be);
    d.push(bytes, &mut out);
    d.finish(&mut out);
    out
}

/// Decode a buffer using a forced encoding, regardless of any byte-order
/// mark it may carry. The caller has declared the encoding; the BOM is
/// treated as data. UTF-8 is the pass-through; UTF-16LE / UTF-16BE go
/// through the same `Utf16` transcoder [`decode`] uses.
pub fn force_decode(bom: Bom, bytes: &[u8]) -> Vec<u8> {
    if bom == Bom::Utf8 {
        return bytes.to_vec();
    }
    decode_utf16(bom == Bom::Utf16Be, bytes)
}

/// Is the whole of this file binary, by the rule a directory walk applies?
///
/// **This is the rule the searchers already apply, written down once so that a
/// caller holding every byte does not have to re-derive it.** `rg`'s binary
/// detection lives inside its searcher and runs over the bytes the matcher is
/// handed, with a byte-order mark already decoded. A caller that has the whole
/// file in memory and wants the same answer without running a search — the pack
/// builder deciding what to ingest — has to apply the rule itself, and the two
/// ways of getting it wrong are both measured:
///
/// - **A head instead of the whole file.** `rgx-tv`'s build sniffed the first
///   kilobyte, so a file holding a NUL at byte 4,000 was ingested as text and
///   the pack answered for it while `rg` and `rgx` both suppressed it. On the
///   cargo registry that is **1,516 lines of `e[0-9]` the pack reports and
///   neither reference does** — a superset, which is the direction a count gate
///   reads as a pass.
/// - **Raw NULs on a marked file.** A UTF-16LE file interleaves `00` after
///   every ASCII character, so a plain `memchr` calls every one of them binary
///   and the pack drops eight files on the registry that `rg` counts, two and
///   twenty-three lines against zero. The mark has to be decoded first, and the
///   decoded NUL is the two-byte code unit U+0000, not a lone NUL.
///
/// The unmarked arm is the whole corpus and stays a single `memchr`, which is
/// why the decode sits behind the mark: only a file opening with `ef bb bf`,
/// `ff fe` or `fe ff` pays for anything else, and that is a handful of files in
/// any tree.
pub fn is_binary(bytes: &[u8]) -> bool {
    match sniff(bytes) {
        // No mark: the bytes the matcher would see are the bytes on disk.
        None => crate::memchr::memchr(0, bytes).is_some(),
        // A UTF-8 mark is not an encoding, it is three bytes of preamble, and
        // the decoder drops them and passes the rest through untouched.
        Some(Bom::Utf8) => crate::memchr::memchr(0, &bytes[Bom::Utf8.len()..]).is_some(),
        Some(bom) => {
            // UTF-16, either order: a decoded NUL is the code unit 0x0000, so
            // two zero bytes on a code-unit boundary. Both orders store that as
            // the same two bytes, so one test serves both, and a trailing odd
            // byte is half a code unit -- which `decode` turns into a
            // replacement character, not a NUL.
            let body = &bytes[bom.len()..];
            let mut at = 0;
            while let Some(off) = crate::memchr::memchr(0, &body[at..]) {
                let i = at + off;
                if i % 2 == 0 && body.get(i + 1) == Some(&0) {
                    return true;
                }
                at = i + 1;
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn u16le(text: &str) -> Vec<u8> {
        let mut v = vec![0xff, 0xfe];
        for u in text.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn u16be(text: &str) -> Vec<u8> {
        let mut v = vec![0xfe, 0xff];
        for u in text.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }

    /// Run the whole raw slice through a `Transcoder`, reading `cap` bytes at a
    /// time so the chunk boundaries are the test's to choose.
    fn through(raw: &[u8], cap: usize) -> Vec<u8> {
        let mut dec = Transcoder::new();
        let mut rest = raw;
        let mut got = Vec::new();
        let mut buf = vec![0u8; cap];
        loop {
            let mut src = |b: &mut [u8]| {
                let k = cmp::min(b.len(), rest.len());
                b[..k].copy_from_slice(&rest[..k]);
                rest = &rest[k..];
                Ok(k)
            };
            let n = dec.read(&mut buf, &mut src).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        got
    }

    /// The whole mark and each byte width.
    #[test]
    fn sniff_picks_the_mark_the_reference_picks() {
        assert_eq!(sniff(b"\xef\xbb\xbfx"), Some(Bom::Utf8));
        assert_eq!(
            sniff(b"\xff\xfe\x00\x00x"),
            Some(Bom::Utf16Le),
            "as UTF-16LE"
        );
        assert_eq!(sniff(b"\xff\xfex\x00"), Some(Bom::Utf16Le));
        assert_eq!(sniff(b"\xfe\xff\x00x"), Some(Bom::Utf16Be));
        assert_eq!(sniff(b"plain"), None);
        assert_eq!(sniff(b""), None);
        assert_eq!(sniff(b"\xff"), None);
        assert_eq!(sniff(b"\xef\xbb"), None);
    }

    #[test]
    fn decode_round_trips_through_both_byte_orders() {
        for bom in [Bom::Utf16Le, Bom::Utf16Be] {
            for text in [
                "",
                "a",
                "alpha\nbeta\n",
                "caf\u{e9} \u{4f60}\u{597d}\n",
                "\u{1f600}!",
            ] {
                let raw = if bom == Bom::Utf16Le {
                    u16le(text)
                } else {
                    u16be(text)
                };
                assert_eq!(
                    String::from_utf8(decode(bom, &raw)).unwrap(),
                    text,
                    "bom={bom:?} text={text:?}"
                );
                for cap in [1usize, 2, 3, 5, 64] {
                    assert_eq!(
                        String::from_utf8(through(&raw, cap)).unwrap(),
                        text,
                        "bom={bom:?} text={text:?} cap={cap}"
                    );
                }
            }
        }
    }

    /// A surrogate pair and a code unit both straddle a read boundary at some
    /// offset, so every offset is walked rather than a convenient one assumed.
    #[test]
    fn a_surrogate_pair_split_across_reads_still_decodes() {
        let raw = u16le("a\u{1f600}b");
        for cap in 1..=raw.len() {
            assert_eq!(
                String::from_utf8(through(&raw, cap)).unwrap(),
                "a\u{1f600}b",
                "cap={cap}"
            );
        }
    }

    /// Unpaired surrogates and a unit the stream ended inside are replacement
    /// characters, so a damaged file is searched rather than skipped.
    #[test]
    fn malformed_input_decodes_to_replacement_characters() {
        // p, then U+1F600 as a pair, then a high surrogate with no partner, Y.
        let paired = b"\xff\xfep\x00\x3d\xd8\x00\xde\x59\x00";
        assert_eq!(
            String::from_utf8(through(paired, 3)).unwrap(),
            "p\u{1f600}Y"
        );
        // A low surrogate with no high one, then a high one with no low one.
        let halves = b"\xff\xfe\x00\xdc\x3d\xd8\x59\x00";
        assert_eq!(
            String::from_utf8(through(halves, 3)).unwrap(),
            "\u{fffd}\u{fffd}Y"
        );
        // An odd number of bytes: the last code unit is incomplete.
        let odd = b"\xff\xfep\x00\x59";
        assert_eq!(String::from_utf8(through(odd, 8)).unwrap(), "p\u{fffd}");
    }

    /// No mark means no work: the caller's buffer is filled from the source
    /// with nothing in between.
    #[test]
    fn an_unmarked_stream_is_passed_through_byte_for_byte() {
        let raw = b"plain ascii\nno mark here\n\xff\xfe not a mark at zero\n";
        for cap in [1usize, 3, 5, 64] {
            assert_eq!(through(raw, cap), raw, "cap={cap}");
        }
        assert_eq!(
            through(b"\xef\xbb\xbfonly a utf-8 mark\n", 5),
            b"only a utf-8 mark\n"
        );
    }

    /// The whole-file binary rule, against the two ways of getting it wrong.
    ///
    /// A head instead of the file is how the pack's build called a file with a
    /// NUL at byte 4,000 text, and 1,516 lines of `e[0-9]` on the cargo
    /// registry are the size of that mistake. A raw NUL on a marked file is how
    /// a UTF-16LE file — half NULs by construction — got called binary and
    /// dropped: eight files on the same registry, against lines ripgrep
    /// counted. Both are pinned here, and so is the odd-byte tail, which is
    /// half a code unit and decodes to a replacement character, not to a NUL.
    #[test]
    fn a_binary_decision_is_over_the_whole_file_and_after_the_mark() {
        // Unmarked, anywhere in the file.
        assert!(!is_binary(b"plain text, no nul at all\n"));
        assert!(is_binary(b"nul at the front\x00"));
        let mut late = vec![b'a'; 4096];
        late.extend_from_slice(b"\x00tail");
        assert!(is_binary(&late), "a NUL at byte 4,096 is still a NUL");
        let mut just_past = vec![b'a'; 1023];
        just_past.push(0);
        assert!(
            is_binary(&just_past),
            "one byte past the old 1 KiB head, which is the whole defect"
        );

        // UTF-8 mark: preamble stripped, and a NUL after it is still a NUL.
        let mut utf8 = b"\xef\xbb\xbf".to_vec();
        utf8.extend_from_slice(b"marked, no nul\n");
        assert!(!is_binary(&utf8));
        let mut utf8_nul = utf8.clone();
        utf8_nul.push(0);
        assert!(is_binary(&utf8_nul));

        // UTF-16, both orders: a NUL is the code unit, never the lone byte that
        // follows every ASCII character in the file.
        for raw in [u16le("plain\nmarked\n"), u16be("plain\nmarked\n")] {
            assert!(!is_binary(&raw), "a UTF-16 file of ASCII is not half NULs");
        }
        for raw in [
            u16le("plain\nmarked\n\u{0}tail\n"),
            u16be("plain\nmarked\n\u{0}tail\n"),
        ] {
            assert!(is_binary(&raw), "a real U+0000 is the code unit 0x0000");
        }
        // Half a code unit at the end is not a NUL, in either order; the pair
        // it completes is.
        for mut raw in [u16le("plain\n"), u16be("plain\n")] {
            raw.push(0);
            assert!(!is_binary(&raw), "an odd tail byte decodes to U+FFFD");
            raw.push(0);
            assert!(is_binary(&raw), "and the code unit it completes is a NUL");
        }
    }
}
