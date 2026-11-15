// SPDX-License-Identifier: Apache-2.0

//! PDF document parser (full version). The sibling `rgx-adapters-pdf` adapter
//! is positional scan + Flate/ASCII85 only — this module is the full reader:
//! classic and stream xref tables, `ObjStm`, the full filter zoo, page-tree
//! walks with inherited `/Resources`, and font decoding through
//! `/ToUnicode` CMaps and the simple-font encodings.
//!
//! ## Boundary
//!
//! A font whose codes cannot be placed is *reported* via
//! `Extraction::undecodable`, never guessed at — `lib.rs` turns that into one
//! `[rgx: pdf: …]` line beside the text that did decode. `/Encrypt` is
//! detected and the standard security handler decrypts the streams whose key
//! reproduces the file's own `/U`; a document whose `/U` does not reproduce
//! is declined, because a wrong key yields bytes that pass every structural
//! check and read as text. Image XObjects are not part of *text* extraction,
//! but the JPEG ones are reachable through [`jpeg_pages`] — a scanned page
//! has no text layer, so its picture is the whole content.
//!
//! ## Filters
//!
//! FlateDecode, LZWDecode (MSB-first, EarlyChange), ASCII85Decode,
//! ASCIIHexDecode, RunLengthDecode, PNG predictors 10–15 via `DecodeParms`.
//! All decoders are in-tree; no external compression crate is used.
//!
//! ## Cross-reference
//!
//! Classic tables, xref streams (`/W`, `/Index`, `/Prev` chains), and
//! hybrid `/XRefStm`. Object streams (`ObjStm`) resolve transparently.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;
use core::fmt::Write as _;
use core::iter;
use core::str;

use crate::fax;
use crate::jbig2;
use crate::security::Security;

/// Everything that can go wrong reading a PDF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdfError {
    /// Does not start with `%PDF-`.
    BadMagic,
    /// Trailer carries `/Encrypt` — text is locked.
    Encrypted,
    /// Encrypted with a scheme, or under a password, this reader does not
    /// implement. The message names the reason, because "encrypted" and
    /// "encrypted with a password I will not guess" are different answers
    /// for whoever is holding the file.
    Security(&'static str),
    /// Structurally invalid input (message says where).
    Parse(&'static str),
}

impl fmt::Display for PdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "not a PDF file (bad magic)"),
            Self::Encrypted => write!(f, "pdf is encrypted"),
            Self::Security(m) => write!(f, "pdf encryption: {m}"),
            Self::Parse(m) => write!(f, "parse error: {m}"),
        }
    }
}

pub type PdfResult<T> = Result<T, PdfError>;

fn parse_err<T>(m: &'static str) -> PdfResult<T> {
    Err(PdfError::Parse(m))
}

// ---------------------------------------------------------------------------
// bit reader (LSB-first, DEFLATE style)
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bitbuf: u32,
    bitcnt: u32,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bitbuf: 0,
            bitcnt: 0,
        }
    }

    fn bit(&mut self) -> Option<u32> {
        if self.bitcnt == 0 {
            let b = *self.data.get(self.pos)?;
            self.pos += 1;
            self.bitbuf = b as u32;
            self.bitcnt = 8;
        }
        let v = self.bitbuf & 1;
        self.bitbuf >>= 1;
        self.bitcnt -= 1;
        Some(v)
    }

    /// n bits, LSB-first (n <= 16)
    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0u32;
        for i in 0..n {
            v |= self.bit()? << i;
        }
        Some(v)
    }

    /// discard bits up to the next byte boundary
    fn align_byte(&mut self) {
        self.bitbuf = 0;
        self.bitcnt = 0;
    }
}

// ---------------------------------------------------------------------------
// canonical Huffman decoding (puff-style: counts + sorted symbols)
// ---------------------------------------------------------------------------

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    /// build from code lengths (0 = unused); None on over-subscription
    fn build(lengths: &[u8]) -> Option<Self> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[l as usize] = counts[l as usize].checked_add(1)?;
        }
        if counts[0] as usize == lengths.len() {
            return None; // no codes at all
        }
        // over-subscription check
        let mut left: i32 = 1;
        for &c in &counts[1..16] {
            left <<= 1;
            left -= c as i32;
            if left < 0 {
                return None;
            }
        }
        // offsets per length
        let mut offs = [0u16; 16];
        for l in 1..15 {
            offs[l + 1] = offs[l] + counts[l];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = sym as u16;
                offs[l as usize] += 1;
            }
        }
        Some(Self { counts, symbols })
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Option<u16> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= br.bit()? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                return Some(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        None
    }
}

// ---------------------------------------------------------------------------
// DEFLATE (RFC 1951) + zlib wrapper (RFC 1950)
// ---------------------------------------------------------------------------

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

const MAX_INFLATE: usize = 256 << 20; // hard cap on any single stream

/// The most xref entries one stream may add to the table. A real PDF has
/// one entry per indirect object and `MAX_PAGES` bounds the objects a
/// page tree can name; a quarter of a billion one-byte rows at the
/// inflate cap is a bomb, not a document.
const MAX_XREF_ENTRIES: usize = 1 << 22;

fn fixed_litlen() -> Huffman {
    let mut l = [0u8; 288];
    for (i, v) in l.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Huffman::build(&l).expect("fixed lit/len table")
}

fn fixed_dist() -> Huffman {
    Huffman::build(&[5u8; 30]).expect("fixed dist table")
}

/// Raw DEFLATE stream → bytes.
pub fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut br = BitReader::new(data);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = br.bit()?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                // stored: LEN/NLEN, then raw bytes
                br.align_byte();
                let p = br.pos;
                let len = u16::from_le_bytes([*data.get(p)?, *data.get(p + 1)?]);
                let nlen = u16::from_le_bytes([*data.get(p + 2)?, *data.get(p + 3)?]);
                if len != !nlen {
                    return None;
                }
                let start = p + 4;
                let end = start.checked_add(len as usize)?;
                out.extend_from_slice(data.get(start..end)?);
                br.pos = end;
            }
            1 => {
                let (l, d) = (fixed_litlen(), fixed_dist());
                inflate_block(&mut br, &l, &d, &mut out)?;
            }
            2 => {
                let hlit = br.bits(5)? as usize + 257;
                let hdist = br.bits(5)? as usize + 1;
                let hclen = br.bits(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl_lens = [0u8; 19];
                for &o in ORDER.iter().take(hclen) {
                    cl_lens[o] = br.bits(3)? as u8;
                }
                let cl = Huffman::build(&cl_lens)?;
                let mut lens = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < hlit + hdist {
                    let sym = cl.decode(&mut br)?;
                    match sym {
                        0..=15 => {
                            lens[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return None;
                            }
                            let prev = lens[i - 1];
                            let rep = 3 + br.bits(2)? as usize;
                            for _ in 0..rep {
                                if i >= lens.len() {
                                    return None;
                                }
                                lens[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let rep = 3 + br.bits(3)? as usize;
                            i = i.checked_add(rep)?;
                        }
                        18 => {
                            let rep = 11 + br.bits(7)? as usize;
                            i = i.checked_add(rep)?;
                        }
                        _ => return None,
                    }
                }
                if i != hlit + hdist {
                    return None;
                }
                let l = Huffman::build(&lens[..hlit])?;
                let d = Huffman::build(&lens[hlit..])?;
                inflate_block(&mut br, &l, &d, &mut out)?;
            }
            _ => return None,
        }
        if out.len() > MAX_INFLATE {
            return None;
        }
        if bfinal == 1 {
            break;
        }
    }
    Some(out)
}

fn inflate_block(
    br: &mut BitReader<'_>,
    litlen: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
) -> Option<()> {
    loop {
        let sym = litlen.decode(br)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Some(()),
            257..=285 => {
                let i = (sym - 257) as usize;
                let len = LEN_BASE[i] as usize + br.bits(LEN_EXTRA[i] as u32)? as usize;
                let dsym = dist.decode(br)? as usize;
                if dsym >= 30 {
                    return None;
                }
                let d = DIST_BASE[dsym] as usize + br.bits(DIST_EXTRA[dsym] as u32)? as usize;
                if d > out.len() {
                    return None; // distance too far back
                }
                let start = out.len() - d;
                // Non-overlapping matches go through `extend_from_within` (one
                // `memmove`); overlapping matches must stay byte-by-byte --
                // a chunked `extend_from_within` would read past the bytes the
                // loop is still writing.
                if d >= len {
                    out.extend_from_within(start..start + len);
                } else {
                    for k in 0..len {
                        out.push(out[start + k]);
                    }
                }
                if out.len() > MAX_INFLATE {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// zlib stream (RFC 1950): validate header, inflate, ignore Adler-32.
pub fn zlib_decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    let cmf = data[0] as u32;
    let flg = data[1] as u32;
    if cmf & 0x0F != 8 || !(cmf * 256 + flg).is_multiple_of(31) || flg & 0x20 != 0 {
        return None; // not deflate, bad check, or preset dictionary
    }
    inflate(&data[2..])
}

// ---------------------------------------------------------------------------
// PNG predictors (DecodeParms /Predictor 10..15)
// ---------------------------------------------------------------------------

/// Undo PNG row filtering. `row_len` = bytes per row (after unfiltering),
/// `bpp` = bytes per complete pixel (>= 1).
pub fn png_predictor(data: &[u8], row_len: usize, bpp: usize) -> Option<Vec<u8>> {
    if row_len == 0 || bpp == 0 {
        return None;
    }
    let stride = row_len + 1; // filter byte + row
    if !data.len().is_multiple_of(stride) {
        return None;
    }
    let rows = data.len() / stride;
    let mut out = vec![0u8; rows * row_len];
    for r in 0..rows {
        let filter = data[r * stride];
        let src = &data[r * stride + 1..(r + 1) * stride];
        let (before, cur) = out.split_at_mut(r * row_len);
        let prev = if r > 0 {
            &before[(r - 1) * row_len..]
        } else {
            &[][..]
        };
        for i in 0..row_len {
            let x = src[i];
            let a = if i >= bpp { cur[i - bpp] } else { 0 };
            let b = if !prev.is_empty() { prev[i] } else { 0 };
            let c = if !prev.is_empty() && i >= bpp {
                prev[i - bpp]
            } else {
                0
            };
            cur[i] = match filter {
                0 => x,
                1 => x.wrapping_add(a),
                2 => x.wrapping_add(b),
                3 => x.wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => x.wrapping_add(paeth(a, b, c)),
                _ => return None,
            };
        }
    }
    Some(out)
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i32 + b as i32 - c as i32;
    let pa = (p - a as i32).abs();
    let pb = (p - b as i32).abs();
    let pc = (p - c as i32).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

// ---------------------------------------------------------------------------
// LZW (PDF variant: MSB-first bit packing, EarlyChange)
// ---------------------------------------------------------------------------

/// PDF LZWDecode. `early_change` is 0 or 1 (default 1).
pub fn lzw_decode(data: &[u8], early_change: u8) -> Option<Vec<u8>> {
    const CLEAR: u16 = 256;
    const EOD: u16 = 257;
    let mut out: Vec<u8> = Vec::new();
    // dictionary: index -> byte string; 0..255 are the roots,
    // 256 = CLEAR and 257 = EOD occupy slots so adds start at 258
    let mut dict: Vec<Vec<u8>> = (0..=255).map(|b| vec![b as u8]).collect();
    dict.push(Vec::new()); // 256 = CLEAR
    dict.push(Vec::new()); // 257 = EOD
    let mut code_size: u32 = 9;
    let mut bitpos: usize = 0; // MSB-first bit position

    let read_code = |bitpos: &mut usize, size: u32| -> Option<u16> {
        let mut v: u32 = 0;
        for _ in 0..size {
            let byte = *data.get(*bitpos / 8)?;
            let bit = (byte >> (7 - (*bitpos % 8))) & 1;
            v = (v << 1) | bit as u32;
            *bitpos += 1;
        }
        Some(v as u16)
    };

    let mut prev: Option<Vec<u8>> = None;
    loop {
        if bitpos / 8 >= data.len() {
            break; // missing EOD: accept what we have
        }
        let code = read_code(&mut bitpos, code_size)?;
        if code == EOD {
            break;
        }
        if code == CLEAR {
            dict.truncate(258);
            code_size = 9;
            prev = None;
            continue;
        }
        let entry: Vec<u8> = if (code as usize) < dict.len() {
            dict[code as usize].clone()
        } else if code as usize == dict.len() {
            // KwKwK: code == next slot, entry = prev + prev[0]
            let p = prev.as_ref()?;
            let mut e = p.clone();
            e.push(p[0]);
            e
        } else {
            return None; // invalid code
        };
        if let Some(p) = &prev {
            if dict.len() < 4096 {
                let mut e = p.clone();
                e.push(entry[0]);
                dict.push(e);
                // PDF: grow when the *next* code would not fit,
                // adjusted by EarlyChange
                if dict.len() as u32 + early_change as u32 >= (1 << code_size) && code_size < 12 {
                    code_size += 1;
                }
            }
        }
        out.extend_from_slice(&entry);
        if out.len() > MAX_INFLATE {
            return None;
        }
        prev = Some(entry);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// ASCII85 / ASCIIHex / RunLength
// ---------------------------------------------------------------------------

/// ASCII85Decode (`<~...~>` optional, `z` shorthand, `u`-padded tail).
pub fn ascii85_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() / 5 * 4 + 8);
    let mut group = [0u32; 5];
    let mut n = 0usize;
    let mut i = if data.starts_with(b"<~") { 2 } else { 0 };
    while i < data.len() {
        let c = data[i];
        i += 1;
        if c == b'~' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'z' && n == 0 {
            out.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !(b'!'..=b'u').contains(&c) {
            return None;
        }
        group[n] = (c - b'!') as u32;
        n += 1;
        if n == 5 {
            // u64 accumulator: 84·85⁴ overflows u32; `as u32` wraps for
            // the pathological all-'u' group, like btoa-class decoders
            let v = group[0] as u64 * 85 * 85 * 85 * 85
                + group[1] as u64 * 85 * 85 * 85
                + group[2] as u64 * 85 * 85
                + group[3] as u64 * 85
                + group[4] as u64;
            out.extend_from_slice(&(v as u32).to_be_bytes());
            n = 0;
        }
    }
    if n > 0 {
        let orig = n;
        while n < 5 {
            group[n] = 84;
            n += 1;
        }
        let v = group[0] as u64 * 85 * 85 * 85 * 85
            + group[1] as u64 * 85 * 85 * 85
            + group[2] as u64 * 85 * 85
            + group[3] as u64 * 85
            + group[4] as u64;
        out.extend_from_slice(&(v as u32).to_be_bytes()[..orig - 1]);
    }
    Some(out)
}

/// ASCIIHexDecode: hex digits until `>`, odd count pads with 0.
pub fn asciihex_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut hi: Option<u8> = None;
    for &c in data {
        let v = match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ if c.is_ascii_whitespace() => None,
            b'>' => break,
            _ => return None,
        };
        match (hi, v) {
            (Some(h), Some(l)) => {
                out.push((h << 4) | l);
                hi = None;
            }
            (None, Some(l)) => hi = Some(l),
            _ => {}
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    Some(out)
}

/// RunLengthDecode: [length byte][literal run] / 128 = EOD,
/// 129..255 = repeat next byte (257 - length) times.
pub fn runlength_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let n = data[i];
        i += 1;
        match n {
            128 => {}
            0..=127 => {
                let end = i.checked_add(n as usize + 1)?;
                out.extend_from_slice(data.get(i..end)?);
                i = end;
            }
            _ => {
                let b = *data.get(i)?;
                i += 1;
                out.extend(iter::repeat_n(b, 257 - n as usize));
            }
        }
        if out.len() > MAX_INFLATE {
            return None;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// object model
// ---------------------------------------------------------------------------

/// A parsed PDF object. Streams keep their *raw* (still encoded) bytes;
/// decoding happens through the filter chain on demand.
#[derive(Debug, Clone, PartialEq)]
pub enum PdfObject {
    Null,
    Bool(bool),
    Int(i64),
    Real(f64),
    Name(String),
    String(Vec<u8>),
    Array(Vec<PdfObject>),
    Dict(Vec<(String, PdfObject)>),
    Ref(u32, u16),
    Stream {
        dict: Vec<(String, PdfObject)>,
        raw: Vec<u8>,
    },
}

impl PdfObject {
    pub(crate) fn dict_get<'a>(
        dict: &'a [(String, PdfObject)],
        key: &str,
    ) -> Option<&'a PdfObject> {
        dict.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            Self::Real(v) => Some(*v as i64),
            _ => None,
        }
    }

    fn as_name(&self) -> Option<&str> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[PdfObject]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub(crate) fn as_dict(&self) -> Option<&[(String, PdfObject)]> {
        match self {
            Self::Dict(d) => Some(d),
            Self::Stream { dict, .. } => Some(dict),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// lexer
// ---------------------------------------------------------------------------

fn is_ws(c: u8) -> bool {
    matches!(c, 0 | b'\t' | b'\n' | b'\x0C' | b'\r' | b' ')
}

fn is_delim(c: u8) -> bool {
    is_ws(c)
        || matches!(
            c,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Str(Vec<u8>),
    Int(i64),
    Real(f64),
    DictOpen,
    DictClose,
    ArrOpen,
    ArrClose,
    Kw(&'static str),
    Eof,
}

struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn skip_ws(&mut self) {
        loop {
            while self.pos < self.data.len() && is_ws(self.data[self.pos]) {
                self.pos += 1;
            }
            if self.pos < self.data.len() && self.data[self.pos] == b'%' {
                while self.pos < self.data.len()
                    && self.data[self.pos] != b'\n'
                    && self.data[self.pos] != b'\r'
                {
                    self.pos += 1;
                }
            } else {
                break;
            }
        }
    }

    /// parse a name starting after `/`; handles `#xx` hex escapes
    fn read_name(&mut self) -> String {
        let mut out = Vec::new();
        while self.pos < self.data.len() && !is_delim(self.data[self.pos]) {
            let c = self.data[self.pos];
            if c == b'#' && self.pos + 2 < self.data.len() {
                let h = hex_val(self.data[self.pos + 1]);
                let l = hex_val(self.data[self.pos + 2]);
                if let (Some(h), Some(l)) = (h, l) {
                    out.push((h << 4) | l);
                    self.pos += 3;
                    continue;
                }
            }
            out.push(c);
            self.pos += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// literal string `( ... )` with nesting and escapes
    fn read_literal_string(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut depth = 1usize;
        self.pos += 1; // consume '('
        while self.pos < self.data.len() {
            let c = self.data[self.pos];
            match c {
                b'(' => {
                    depth += 1;
                    out.push(c);
                    self.pos += 1;
                }
                b')' => {
                    depth -= 1;
                    self.pos += 1;
                    if depth == 0 {
                        break;
                    }
                    out.push(c);
                }
                b'\\' => {
                    self.pos += 1;
                    if self.pos >= self.data.len() {
                        break;
                    }
                    let e = self.data[self.pos];
                    match e {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'(' | b')' | b'\\' => out.push(e),
                        b'\n' => {}
                        b'\r' => {
                            if self.data.get(self.pos + 1) == Some(&b'\n') {
                                self.pos += 1;
                            }
                        }
                        d @ b'0'..=b'7' => {
                            let mut v = (d - b'0') as u32;
                            let mut n = 1;
                            while n < 3
                                && self.pos + 1 < self.data.len()
                                && matches!(self.data[self.pos + 1], b'0'..=b'7')
                            {
                                self.pos += 1;
                                v = (v << 3) | (self.data[self.pos] - b'0') as u32;
                                n += 1;
                            }
                            out.push(v as u8);
                        }
                        other => out.push(other),
                    }
                    self.pos += 1;
                }
                _ => {
                    out.push(c);
                    self.pos += 1;
                }
            }
        }
        out
    }

    /// hex string `< ... >` (caller consumed `<`, not `<<`)
    fn read_hex_string(&mut self) -> Vec<u8> {
        let mut nibbles = Vec::new();
        self.pos += 1; // consume '<'
        while self.pos < self.data.len() && self.data[self.pos] != b'>' {
            let c = self.data[self.pos];
            if let Some(v) = hex_val(c) {
                nibbles.push(v);
            }
            // whitespace and stray bytes are skipped per spec leniency
            self.pos += 1;
        }
        if self.pos < self.data.len() {
            self.pos += 1; // consume '>'
        }
        if nibbles.len() % 2 == 1 {
            nibbles.push(0);
        }
        nibbles
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| (c[0] << 4) | c[1])
            .collect()
    }

    fn read_number(&mut self, first: u8) -> Tok {
        let start = self.pos;
        self.pos += 1; // first digit or sign
        while self.pos < self.data.len()
            && (self.data[self.pos].is_ascii_digit() || self.data[self.pos] == b'.')
        {
            self.pos += 1;
        }
        // exponent (rare in PDFs but legal)
        if self.pos < self.data.len() && matches!(self.data[self.pos], b'e' | b'E') {
            let save = self.pos;
            self.pos += 1;
            if self.pos < self.data.len() && matches!(self.data[self.pos], b'+' | b'-') {
                self.pos += 1;
            }
            if self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
                while self.pos < self.data.len() && self.data[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
            } else {
                self.pos = save;
            }
        }
        let _ = first;
        let text = str::from_utf8(&self.data[start..self.pos]).unwrap_or("");
        if text.contains('.') || text.contains('e') || text.contains('E') {
            parse_real(text).map(Tok::Real).unwrap_or(Tok::Int(0))
        } else {
            parse_int(text).map(Tok::Int).unwrap_or(Tok::Int(0))
        }
    }

    /// The next token, skipping the two cases that have no token of their
    /// own: a lone `>`, and a byte that cannot start one.
    ///
    /// Both are a `continue`, not a call. They used to be tail calls to
    /// `next_tok`, which made the stack depth a function of how long a run
    /// of unparseable bytes is: `fuzzkit` found this the moment a corpus
    /// held a PDF large enough to mutate into a few kilobytes of `0xFF`,
    /// and the reader took the thread's stack with it on the way to
    /// returning a perfectly good `Bail`. A loop costs the same and has a
    /// bound of one.
    fn next_tok(&mut self) -> Tok {
        loop {
            self.skip_ws();
            if self.pos >= self.data.len() {
                return Tok::Eof;
            }
            let c = self.data[self.pos];
            match c {
                b'/' => {
                    self.pos += 1;
                    return Tok::Name(self.read_name());
                }
                b'(' => return Tok::Str(self.read_literal_string()),
                b'<' => {
                    if self.data.get(self.pos + 1) == Some(&b'<') {
                        self.pos += 2;
                        return Tok::DictOpen;
                    }
                    return Tok::Str(self.read_hex_string());
                }
                b'>' => {
                    if self.data.get(self.pos + 1) == Some(&b'>') {
                        self.pos += 2;
                        return Tok::DictClose;
                    }
                    self.pos += 1;
                    continue; // lone '>' closes nothing
                }
                b'[' => {
                    self.pos += 1;
                    return Tok::ArrOpen;
                }
                b']' => {
                    self.pos += 1;
                    return Tok::ArrClose;
                }
                b'+' | b'-' | b'.' | b'0'..=b'9' => return self.read_number(c),
                _ => {
                    // keyword: letters/digits/*/'/"
                    let start = self.pos;
                    while self.pos < self.data.len()
                        && (self.data[self.pos].is_ascii_alphanumeric()
                            || matches!(self.data[self.pos], b'*' | b'\'' | b'"'))
                    {
                        self.pos += 1;
                    }
                    if self.pos == start {
                        self.pos += 1; // stray byte
                        continue;
                    }
                    return match &self.data[start..self.pos] {
                        b"true" => Tok::Kw("true"),
                        b"false" => Tok::Kw("false"),
                        b"null" => Tok::Kw("null"),
                        b"obj" => Tok::Kw("obj"),
                        b"endobj" => Tok::Kw("endobj"),
                        b"stream" => Tok::Kw("stream"),
                        b"endstream" => Tok::Kw("endstream"),
                        b"R" => Tok::Kw("R"),
                        b"xref" => Tok::Kw("xref"),
                        b"trailer" => Tok::Kw("trailer"),
                        b"startxref" => Tok::Kw("startxref"),
                        b"n" => Tok::Kw("n"),
                        b"f" => Tok::Kw("f"),
                        _ => Tok::Kw("?"),
                    };
                }
            }
        }
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn parse_int(s: &str) -> Option<i64> {
    let mut v: i64 = 0;
    let mut sign = 1i64;
    let mut it = s.bytes().peekable();
    if it.peek() == Some(&b'-') {
        sign = -1;
        it.next();
    } else if it.peek() == Some(&b'+') {
        it.next();
    }
    let mut any = false;
    for c in it {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((c - b'0') as i64)?;
        any = true;
    }
    if any {
        Some(sign * v)
    } else {
        None
    }
}

/// no_std float parse: [+-]digits[.digits][e[+-]digits]
fn parse_real(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut sign = 1.0f64;
    if b.get(i) == Some(&b'-') {
        sign = -1.0;
        i += 1;
    } else if b.get(i) == Some(&b'+') {
        i += 1;
    }
    let mut v = 0.0f64;
    let mut any = false;
    while i < b.len() && b[i].is_ascii_digit() {
        v = v * 10.0 + (b[i] - b'0') as f64;
        i += 1;
        any = true;
    }
    if b.get(i) == Some(&b'.') {
        i += 1;
        let mut scale = 0.1f64;
        while i < b.len() && b[i].is_ascii_digit() {
            v += (b[i] - b'0') as f64 * scale;
            scale *= 0.1;
            i += 1;
            any = true;
        }
    }
    if !any {
        return None;
    }
    if b.get(i) == Some(&b'e') || b.get(i) == Some(&b'E') {
        i += 1;
        let mut esign = 1.0f64;
        if b.get(i) == Some(&b'-') {
            esign = -1.0;
            i += 1;
        } else if b.get(i) == Some(&b'+') {
            i += 1;
        }
        let mut e = 0i32;
        let mut eany = false;
        while i < b.len() && b[i].is_ascii_digit() {
            e = e.checked_mul(10)?.checked_add((b[i] - b'0') as i32)?;
            i += 1;
            eany = true;
        }
        if !eany {
            return None;
        }
        v *= 10f64.powi(esign as i32 * e);
    }
    Some(sign * v)
}

// ---------------------------------------------------------------------------
// object parser
// ---------------------------------------------------------------------------

/// How deep `[` and `<<` may nest before the object is refused. Real PDFs
/// nest under 30. The cap is the same defence as the loop in `Lexer::next_tok`
/// and for the same reason — this recursion is one stack frame per level, and
/// a file that opens 100,000 brackets is not a document, it is a way to run
/// the searcher off its stack before it gets to say `Bail`. `next_tok` is
/// where `rgx_core::fuzzkit` actually found the hole (6.5 KB of `0xFF` in a
/// mutated fixture, one frame each); this one is the same class of input and
/// is closed for the same reason. `MAX_TREE_DEPTH` bounds the page tree.
const MAX_OBJ_DEPTH: u32 = 256;

/// Parse one object starting at the lexer's current position. `depth`
/// counts `[` and `<<` nesting; 0 is the outermost object of an object.
fn parse_object(l: &mut Lexer<'_>, depth: u32) -> PdfResult<PdfObject> {
    // lookahead: "N G obj" header or "N G R" reference
    let save = l.pos;
    let t = l.next_tok();
    if let Tok::Int(num) = t {
        let t2 = l.next_tok();
        if let Tok::Int(gen_num) = t2 {
            let t3 = l.next_tok();
            match t3 {
                Tok::Kw("R") => {
                    return Ok(PdfObject::Ref(num as u32, gen_num as u16));
                }
                Tok::Kw("obj") => {
                    let obj = parse_object(l, depth)?;
                    let end = l.next_tok();
                    if end != Tok::Kw("endobj") {
                        // tolerate missing endobj at EOF
                    }
                    return Ok(obj);
                }
                _ => {
                    // not a header/ref: rewind and parse the first int
                    l.pos = save;
                }
            }
        } else {
            l.pos = save;
        }
    } else {
        l.pos = save;
    }
    parse_simple(l, depth)
}

fn parse_simple(l: &mut Lexer<'_>, depth: u32) -> PdfResult<PdfObject> {
    if depth > MAX_OBJ_DEPTH {
        return parse_err("object nesting too deep");
    }
    match l.next_tok() {
        Tok::Int(v) => Ok(PdfObject::Int(v)),
        Tok::Real(v) => Ok(PdfObject::Real(v)),
        Tok::Name(n) => Ok(PdfObject::Name(n)),
        Tok::Str(b) => Ok(PdfObject::String(b)),
        Tok::Kw("true") => Ok(PdfObject::Bool(true)),
        Tok::Kw("false") => Ok(PdfObject::Bool(false)),
        Tok::Kw("null") => Ok(PdfObject::Null),
        Tok::Kw("?") => parse_err("unknown keyword"),
        Tok::ArrOpen => {
            let mut items = Vec::new();
            loop {
                let save = l.pos;
                match l.next_tok() {
                    Tok::ArrClose => break,
                    Tok::Eof => return parse_err("unterminated array"),
                    _ => {
                        l.pos = save;
                        items.push(parse_object(l, depth + 1)?);
                    }
                }
            }
            Ok(PdfObject::Array(items))
        }
        Tok::DictOpen => {
            let mut dict = Vec::new();
            loop {
                match l.next_tok() {
                    Tok::DictClose => break,
                    Tok::Eof => return parse_err("unterminated dict"),
                    Tok::Name(k) => {
                        let v = parse_object(l, depth + 1)?;
                        dict.push((k, v));
                    }
                    _ => return parse_err("dict key is not a name"),
                }
            }
            // stream? peek the keyword after the dict
            let save = l.pos;
            if matches!(l.next_tok(), Tok::Kw("stream")) {
                // EOL after `stream`
                if l.data.get(l.pos) == Some(&b'\r') {
                    l.pos += 1;
                }
                if l.data.get(l.pos) == Some(&b'\n') {
                    l.pos += 1;
                }
                let start = l.pos;
                // length: try direct int; indirect refs resolved by caller
                let len = PdfObject::dict_get(&dict, "Length")
                    .and_then(|v| v.as_int())
                    .filter(|&n| n >= 0);
                let raw = match len {
                    Some(n) => {
                        let end = start.saturating_add(n as usize).min(l.data.len());
                        // trust /Length; an early endstream inside the window
                        // wins (defensive against corrupt lengths)
                        match find_bytes(&l.data[start..end], b"endstream") {
                            Some(r) => l.data[start..start + r].to_vec(),
                            None => l.data[start..end].to_vec(),
                        }
                    }
                    None => {
                        // indirect /Length: nearest endstream ahead of the
                        // data (a backwards search would be O(file) here)
                        match find_bytes(&l.data[start..], b"endstream") {
                            Some(r) => {
                                let mut end = start + r;
                                if end > start && l.data[end - 1] == b'\n' {
                                    end -= 1;
                                }
                                if end > start && l.data[end - 1] == b'\r' {
                                    end -= 1;
                                }
                                l.data[start..end].to_vec()
                            }
                            None => return parse_err("stream without endstream"),
                        }
                    }
                };
                l.pos = start + raw.len();
                Ok(PdfObject::Stream { dict, raw })
            } else {
                l.pos = save;
                Ok(PdfObject::Dict(dict))
            }
        }
        Tok::Eof => parse_err("unexpected eof"),
        _ => parse_err("unexpected token"),
    }
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Last occurrence of `needle`, as a byte offset into `hay`.
///
/// `memmem::rfind` is the SIMD primitive for this. The previous body was
/// `hay.windows(needle.len()).rposition(|w| w == needle)` — one window
/// construction and one compare per byte, over the whole file — and it has one
/// production caller: the `startxref` search at the bottom of the file, which
/// for a 50 MB PDF is 50 million of them to read something the format puts
/// within the last kilobyte or so.
///
/// The forward twin `find_bytes` is left alone: it has callers that genuinely
/// do need to sweep, and one call site at a time is what this change claims.
fn rfind_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    rgx_core::memchr::memmem::rfind(hay, needle)
}

// ---------------------------------------------------------------------------
// filters dispatcher (with DecodeParms)
// ---------------------------------------------------------------------------

/// DecodeParms relevant subset.
#[derive(Debug, Clone, Copy, Default)]
struct DecodeParms {
    predictor: i64,
    colors: i64,
    bpc: i64,
    columns: i64,
    early_change: i64,
    /// `/K` for `/CCITTFaxDecode`: 0 is Group 4, -1 is Group 3, and a
    /// positive value is a 1D-row count within mixed-coded 2D rows.
    k: i64,
    /// `/Rows`; 0 and "absent" both mean the height the dictionary states.
    rows: i64,
    /// `/BlackIs1`. PDF's default is `false`, so the default here is too and
    /// reading an absent entry as `true` inverts every scan in the corpus.
    black_is_1: i64,
    /// `/EncodedByteAlign`.
    byte_align: i64,
}

fn parms_from_dict(dict: &[(String, PdfObject)]) -> DecodeParms {
    let get = |k: &str, d: i64| {
        PdfObject::dict_get(dict, k)
            .and_then(|v| v.as_int())
            .unwrap_or(d)
    };
    DecodeParms {
        k: get("K", 0),
        rows: get("Rows", 0),
        black_is_1: get("BlackIs1", 0),
        byte_align: get("EncodedByteAlign", 0),
        predictor: get("Predictor", 1),
        colors: get("Colors", 1),
        bpc: get("BitsPerComponent", 8),
        columns: get("Columns", 1),
        early_change: get("EarlyChange", 1),
    }
}

fn apply_predictor(data: Vec<u8>, p: DecodeParms) -> Option<Vec<u8>> {
    if !(10..=15).contains(&p.predictor) {
        return Some(data);
    }
    // TIFF predictor 2 (horizontal differencing) is rare; decline softly
    if p.predictor == 2 {
        return None;
    }
    let bpp_bits = p.colors.checked_mul(p.bpc)?.max(1);
    let row_len = ((p.columns.checked_mul(bpp_bits)? + 7) / 8) as usize;
    let bpp = ((bpp_bits + 7) / 8) as usize;
    png_predictor(&data, row_len, bpp)
}

/// Apply one filter by name, with optional parms.
fn apply_filter(name: &str, data: Vec<u8>, p: DecodeParms) -> Option<Vec<u8>> {
    let decoded = match name {
        "FlateDecode" | "Fl" => zlib_decode(&data)?,
        "LZWDecode" | "LZW" => lzw_decode(&data, p.early_change.clamp(0, 1) as u8)?,
        "ASCII85Decode" | "A85" => ascii85_decode(&data)?,
        "ASCIIHexDecode" | "AHx" => asciihex_decode(&data)?,
        "RunLengthDecode" | "RL" => runlength_decode(&data)?,
        _ => return None,
    };
    apply_predictor(decoded, p)
}

/// Decode a stream's raw bytes through its /Filter + /DecodeParms chain.
fn decode_stream_data(dict: &[(String, PdfObject)], raw: &[u8]) -> Option<Vec<u8>> {
    let Some(filter) = PdfObject::dict_get(dict, "Filter") else {
        return Some(raw.to_vec());
    };
    let empty = DecodeParms::default();
    let names: Vec<&str> = match filter {
        PdfObject::Name(n) => vec![n.as_str()],
        PdfObject::Array(a) => a.iter().filter_map(|v| v.as_name()).collect(),
        _ => return None,
    };
    let parms_list: Vec<DecodeParms> = match PdfObject::dict_get(dict, "DecodeParms")
        .or_else(|| PdfObject::dict_get(dict, "DP"))
    {
        Some(PdfObject::Array(a)) => a
            .iter()
            .map(|v| v.as_dict().map(parms_from_dict).unwrap_or(empty))
            .collect(),
        Some(PdfObject::Dict(d)) => vec![parms_from_dict(d)],
        _ => vec![],
    };
    let mut data = raw.to_vec();
    for (i, name) in names.iter().enumerate() {
        let p = parms_list.get(i).copied().unwrap_or(empty);
        data = apply_filter(name, data, p)?;
    }
    Some(data)
}

// ---------------------------------------------------------------------------
// xref: classic tables and xref streams
// ---------------------------------------------------------------------------

/// One xref entry. kind: 0 free, 1 uncompressed (f2=offset, f3=gen),
/// 2 compressed in an ObjStm (f2=stm num, f3=index inside).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XrefEntry {
    kind: u8,
    f2: u64,
    f3: u64,
}

/// Parse a classic `xref` section at `pos` (lexer positioned after the
/// `xref` keyword). Returns entries and the trailer dict.
fn parse_xref_classic(
    data: &[u8],
    mut pos: usize,
    entries: &mut BTreeMap<u32, XrefEntry>,
) -> PdfResult<(Vec<(String, PdfObject)>, usize)> {
    loop {
        // section header: start count
        skip_ws_at(data, &mut pos);
        let start = read_uint_at(data, &mut pos).ok_or(PdfError::Parse("xref start"))?;
        skip_ws_at(data, &mut pos);
        let count = read_uint_at(data, &mut pos).ok_or(PdfError::Parse("xref count"))?;
        // each entry is exactly 20 bytes: "oooooooooo ggggg n/f\r\n"
        for i in 0..count {
            skip_ws_at(data, &mut pos);
            let off = read_fixed_uint(data, &mut pos, 10)?;
            skip_ws_at(data, &mut pos);
            let gen_num = read_fixed_uint(data, &mut pos, 5)?;
            skip_ws_at(data, &mut pos);
            let kind = match data.get(pos) {
                Some(b'n') => 1u8,
                Some(b'f') => 0u8,
                _ => return parse_err("xref entry kind"),
            };
            pos += 1;
            entries.entry((start + i) as u32).or_insert(XrefEntry {
                kind,
                f2: off,
                f3: gen_num,
            });
        }
        skip_ws_at(data, &mut pos);
        if data.get(pos..pos + 7) == Some(b"trailer") {
            pos += 7;
            let mut l = Lexer { data, pos };
            let trailer = match parse_simple(&mut l, 0)? {
                PdfObject::Dict(d) => d,
                _ => return parse_err("trailer is not a dict"),
            };
            return Ok((trailer, l.pos));
        }
        // another xref section (multi-section files)
        if data.get(pos..pos + 4) == Some(b"xref") {
            pos += 4;
            continue;
        }
        return parse_err("xref section without trailer");
    }
}

/// Parse an xref *stream* object whose header starts at `pos`.
fn parse_xref_stream(
    data: &[u8],
    pos: usize,
    entries: &mut BTreeMap<u32, XrefEntry>,
) -> PdfResult<(Vec<(String, PdfObject)>, usize)> {
    let mut l = Lexer { data, pos };
    let obj = parse_object(&mut l, 0)?;
    let PdfObject::Stream { dict, raw } = obj else {
        return parse_err("xref stream is not a stream");
    };
    let decoded = decode_stream_data(&dict, &raw).ok_or(PdfError::Parse("xref stream filters"))?;
    let w = PdfObject::dict_get(&dict, "W")
        .and_then(|v| v.as_array())
        .ok_or(PdfError::Parse("xref stream /W"))?;
    let w: Vec<usize> = w
        .iter()
        .filter_map(|v| v.as_int().map(|n| n as usize))
        .collect();
    if w.len() < 3 {
        return parse_err("xref stream /W too short");
    }
    // The widths are fields of the file, and a negative one cast to
    // usize is a huge one: the row length used to wrap on it and a
    // zero row length walked `Index` forever on a stream that held no
    // rows at all. The PDF spec caps every field at 8 bytes, and a row
    // must cost at least one byte of the decoded stream or no row can
    // exist. The total row count is bounded by the stream's own length.
    if w.iter().any(|&x| x > 8) {
        return parse_err("xref stream /W field wider than 8 bytes");
    }
    let row_len: usize = w.iter().sum();
    if row_len == 0 || row_len > decoded.len() {
        return parse_err("xref stream /W row does not fit the stream");
    }
    let size = PdfObject::dict_get(&dict, "Size")
        .and_then(|v| v.as_int())
        .unwrap_or(0) as u32;
    let index: Vec<u32> = match PdfObject::dict_get(&dict, "Index") {
        Some(PdfObject::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_int().map(|n| n as u32))
            .collect(),
        _ => vec![0, size],
    };
    let read_field = |row: &[u8], start: usize, len: usize| -> u64 {
        let mut v: u64 = 0;
        for k in 0..len {
            v = (v << 8) | row.get(start + k).copied().unwrap_or(0) as u64;
        }
        v
    };
    // A stream of N bytes holds N/row_len rows at most; the entry map is
    // also ceilinged, because a `count` from /Index walks before the
    // rows run out only on a stream at the inflate cap, and 256 MB of
    // one-byte rows is still a quarter of a billion map entries.
    let max_rows = decoded.len() / row_len;
    let mut rows_read = 0usize;
    let mut row_pos = 0usize;
    for pair in index.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let (start, count) = (pair[0], pair[1]);
        for i in 0..count {
            if rows_read >= max_rows || entries.len() >= MAX_XREF_ENTRIES {
                break;
            }
            let row = &decoded[row_pos..row_pos + row_len];
            row_pos += row_len;
            rows_read += 1;
            let kind = if w[0] == 0 {
                1
            } else {
                read_field(row, 0, w[0]) as u8
            };
            let f2 = read_field(row, w[0], w[1]);
            let f3 = read_field(row, w[0] + w[1], w[2]);
            let Some(id) = start.checked_add(i) else {
                break;
            };
            entries.entry(id).or_insert(XrefEntry { kind, f2, f3 });
        }
    }
    Ok((dict, l.pos))
}

fn skip_ws_at(data: &[u8], pos: &mut usize) {
    while *pos < data.len() && is_ws(data[*pos]) {
        *pos += 1;
    }
}

fn read_uint_at(data: &[u8], pos: &mut usize) -> Option<u64> {
    let start = *pos;
    while *pos < data.len() && data[*pos].is_ascii_digit() {
        *pos += 1;
    }
    if *pos == start {
        return None;
    }
    let mut v: u64 = 0;
    for &c in &data[start..*pos] {
        v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(v)
}

fn read_fixed_uint(data: &[u8], pos: &mut usize, digits: usize) -> PdfResult<u64> {
    let mut v: u64 = 0;
    for _ in 0..digits {
        let c = *data
            .get(*pos)
            .ok_or(PdfError::Parse("xref entry truncated"))?;
        if !c.is_ascii_digit() {
            return parse_err("xref entry not numeric");
        }
        v = v * 10 + (c - b'0') as u64;
        *pos += 1;
    }
    Ok(v)
}

/// skip whitespace at `pos`, then read a decimal integer
fn read_uint_at_after(data: &[u8], mut pos: usize) -> Option<u64> {
    skip_ws_at(data, &mut pos);
    read_uint_at(data, &mut pos)
}

// ---------------------------------------------------------------------------
// document
// ---------------------------------------------------------------------------

/// A parsed PDF document: xref, trailer chain and object cache.
pub struct PdfDocument<'a> {
    data: &'a [u8],
    entries: BTreeMap<u32, XrefEntry>,
    trailer: Vec<(String, PdfObject)>,
    cache: RefCell<BTreeMap<u32, PdfObject>>,
    /// `Some` only for a document the standard security handler could open
    /// and prove. Every byte that reaches the searcher has been through it.
    sec: Option<Security>,
}

impl<'a> PdfDocument<'a> {
    /// Parse the full document: load `startxref`, walk the `/Prev` chain
    /// (classic and stream xrefs, hybrid `/XRefStm`), merge trailers.
    pub fn parse(data: &'a [u8]) -> PdfResult<Self> {
        if !data.starts_with(b"%PDF-") {
            return Err(PdfError::BadMagic);
        }
        let mut entries: BTreeMap<u32, XrefEntry> = BTreeMap::new();
        let mut trailer_merged: Vec<(String, PdfObject)> = Vec::new();

        // startxref: last occurrence wins (incremental updates)
        let pos = match rfind_bytes(data, b"startxref") {
            Some(r) => r + 9,
            None => {
                // no xref at all: brute-scan fallback (rgx minimal mode)
                return Self::parse_bruteforce(data);
            }
        };
        let mut seen_sections = 0usize;
        // the startxref offset points at the newest xref section
        let mut section = match read_uint_at_after(data, pos) {
            Some(off) if (off as usize) < data.len() => off as usize,
            _ => return Self::parse_bruteforce(data),
        };
        loop {
            if seen_sections > 64 || section >= data.len() {
                break; // cyclic /Prev: stop, use what we have
            }
            seen_sections += 1;
            let (trailer, _next) = if data.get(section..section + 4) == Some(b"xref") {
                parse_xref_classic(data, section + 4, &mut entries)?
            } else {
                parse_xref_stream(data, section, &mut entries)?
            };
            // hybrid-reference file: trailer also points at an xref stream
            if let Some(&PdfObject::Int(xstm)) = PdfObject::dict_get(&trailer, "XRefStm") {
                if xstm >= 0 && (xstm as usize) < data.len() {
                    let _ = parse_xref_stream(data, xstm as usize, &mut entries);
                }
            }
            // follow /Prev from THIS section's trailer (before merging,
            // otherwise an older section's missing /Prev re-loops us)
            let prev = PdfObject::dict_get(&trailer, "Prev").and_then(|v| v.as_int());
            merge_trailer(&mut trailer_merged, trailer);
            match prev {
                Some(p) if p >= 0 && (p as usize) < data.len() => {
                    section = p as usize;
                }
                _ => break,
            }
        }

        if entries.is_empty() {
            return Self::parse_bruteforce(data);
        }
        let mut doc = Self {
            data,
            entries,
            trailer: trailer_merged,
            cache: RefCell::new(BTreeMap::new()),
            sec: None,
        };
        doc.init_security()?;
        Ok(doc)
    }

    /// Work out how this document is encrypted, if at all.
    ///
    /// The order matters and is not negotiable: the `/ID` must be read before
    /// anything that consults the key, because the key is derived *from* it.
    /// A document whose `/Encrypt` names a scheme this crate does not
    /// implement, or whose user password is not empty, comes back as an
    /// `Err` — which the adapter turns into a bail, leaving the raw bytes
    /// searchable. That is the honest outcome: the alternative is a page of
    /// decrypted-looking noise that nobody can distinguish from text.
    fn init_security(&mut self) -> PdfResult<()> {
        let enc_obj = match PdfObject::dict_get(&self.trailer, "Encrypt") {
            Some(e) => e.clone(),
            None => return Ok(()),
        };
        let enc_dict = match self.deref(&enc_obj) {
            Some(PdfObject::Dict(d)) => d,
            // A trailer pointing at something that is not a dictionary is
            // still an encrypted document, and the pipeline's answer for it
            // is the same as for one it cannot decrypt.
            _ => return Err(PdfError::Encrypted),
        };

        // `/ID` is `[<hex> <hex>]`; only the first element feeds the key.
        let id: Vec<u8> = match PdfObject::dict_get(&self.trailer, "ID") {
            Some(PdfObject::Array(a)) => match a.first() {
                Some(PdfObject::String(b)) => b.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };

        self.sec = Some(Security::new(&enc_dict, &id).map_err(PdfError::from)?);
        Ok(())
    }

    /// Fallback for files without a usable xref: positional object scan
    /// (the rgx minimal strategy, but through the same resolver API).
    fn parse_bruteforce(data: &'a [u8]) -> PdfResult<Self> {
        let mut entries: BTreeMap<u32, XrefEntry> = BTreeMap::new();
        let mut i = 0usize;
        let mut count = 0usize;
        while i + 4 <= data.len() && count < 500_000 {
            let Some(rel) = find_bytes(&data[i..], b"obj") else {
                break;
            };
            let p = i + rel;
            // "N G obj" header check
            let mut q = p;
            while q > 0 && data[q - 1].is_ascii_whitespace() {
                q -= 1;
            }
            let gen_end = q;
            while q > 0 && data[q - 1].is_ascii_digit() {
                q -= 1;
            }
            while q > 0 && data[q - 1].is_ascii_whitespace() {
                q -= 1;
            }
            let num_end = q;
            while q > 0 && data[q - 1].is_ascii_digit() {
                q -= 1;
            }
            if q == num_end || q == gen_end || (q > 0 && !data[q - 1].is_ascii_whitespace()) {
                i = p + 3;
                continue;
            }
            let Ok(num) = str::from_utf8(&data[q..num_end])
                .unwrap_or("")
                .parse::<u32>()
            else {
                i = p + 3;
                continue;
            };
            entries.entry(num).or_insert(XrefEntry {
                kind: 1,
                f2: q as u64,
                f3: 0,
            });
            count += 1;
            i = p + 3;
        }
        if entries.is_empty() {
            return parse_err("no xref and no objects found");
        }
        Ok(Self {
            data,
            entries,
            trailer: Vec::new(),
            cache: RefCell::new(BTreeMap::new()),
            sec: None,
        })
    }

    /// Resolve an indirect object (through the cache, through ObjStm).
    pub fn resolve(&self, num: u32) -> Option<PdfObject> {
        self.resolve_at(num, 0)
    }

    fn resolve_at(&self, num: u32, depth: usize) -> Option<PdfObject> {
        if depth > 8 {
            return None; // self-referential ObjStm chains
        }
        if let Some(o) = self.cache.borrow().get(&num) {
            return Some(o.clone());
        }
        let entry = *self.entries.get(&num)?;
        let obj = match entry.kind {
            1 => {
                let mut l = Lexer {
                    data: self.data,
                    pos: entry.f2 as usize,
                };
                parse_object(&mut l, 0).ok()?
            }
            2 => self.resolve_in_objstm(num, entry, depth + 1)?,
            _ => return None,
        };
        self.cache.borrow_mut().insert(num, obj.clone());
        Some(obj)
    }

    /// deref: resolve refs, pass everything else through
    pub fn deref(&self, obj: &PdfObject) -> Option<PdfObject> {
        match obj {
            PdfObject::Ref(n, _) => self.resolve(*n),
            other => Some(other.clone()),
        }
    }

    /// True when this document was opened through a proved key, as opposed
    /// to simply not carrying an `/Encrypt` dictionary. The test corpus needs
    /// to tell those apart: a document that never needed a key and a document
    /// whose key was derived and checked are not the same evidence.
    #[cfg(test)]
    pub fn is_encrypted_open(&self) -> bool {
        self.sec.is_some()
    }

    /// The generation number of an object, which the per-object key mixes in
    /// alongside the object number.
    ///
    /// The cross-reference table is the authority, not the `Ref` token: the
    /// token carries the generation the *writer* had when the reference was
    /// written, and the two disagree in exactly the incremental-update case
    /// that a real corpus contains.
    ///
    /// An object inside an object stream has generation 0 by definition —
    /// `/ObjStm` entries are not independently addressable generations.
    fn gen_of(&self, num: u32) -> u16 {
        match self.entries.get(&num) {
            Some(e) if e.kind == 1 => e.f3 as u16,
            _ => 0,
        }
    }

    /// Decrypt and fully decode one stream object.
    ///
    /// The two steps are inseparable from a caller's point of view and the
    /// order is fixed: the writer compressed, then encrypted, so the reader
    /// decrypts, then decompresses. Getting this backwards produces a stream
    /// that fails to inflate, which is at least loud — but only because the
    /// wrong order is not the one that produces plausible output.
    pub(crate) fn decode_stream(&self, obj: &PdfObject) -> Option<Vec<u8>> {
        // A direct stream carries no object number of its own unless it was
        // written as one, in which case `/Length` and `/Filter` are all we
        // need and there is nothing to decrypt with.
        let num = match obj {
            PdfObject::Ref(n, _) => *n,
            PdfObject::Stream { .. } => return self.decode_direct_stream(obj),
            _ => return None,
        };
        let PdfObject::Stream { dict, raw } = self.resolve(num)? else {
            return None;
        };
        let plain = self.stream_ciphertext(obj, &raw)?;
        decode_stream_data(&dict, &plain)
    }

    /// Undo the encryption on a stream's stored bytes, leaving any `/Filter`
    /// chain alone. `raw` is the value the object resolved to, passed in so
    /// callers that already have it do not resolve twice.
    ///
    /// Returns `None` when the bytes cannot be decrypted — a wrong-length
    /// AES ciphertext, say. Skipping that one object is the right answer:
    /// the page loses a stream, and the document still reports what it can
    /// actually read.
    fn stream_ciphertext(&self, obj: &PdfObject, raw: &[u8]) -> Option<Vec<u8>> {
        let Some(sec) = &self.sec else {
            return Some(raw.to_vec());
        };
        let PdfObject::Ref(num, _) = obj else {
            // A stream reached without a reference has no object number, and
            // the per-object key is built from one. It cannot have come from
            // an encrypted document, so this is the raw bytes unchanged.
            return Some(raw.to_vec());
        };
        sec.decrypt_stream(*num, self.gen_of(*num), raw)
    }

    fn decode_direct_stream(&self, obj: &PdfObject) -> Option<Vec<u8>> {
        let PdfObject::Stream { dict, raw } = obj else {
            return None;
        };
        decode_stream_data(dict, raw)
    }

    /// The file key this document opened with, for tests that check the
    /// derivation against a reference implementation's own number.
    #[cfg(test)]
    pub(crate) fn security_key(&self) -> Vec<u8> {
        self.sec.as_ref().map(|s| s.key.clone()).unwrap_or_default()
    }

    /// Decrypt a string that belongs to object `num`'s dictionary, or return
    /// it untouched when the document is not encrypted.
    fn decrypt_string_of(&self, num: u32, bytes: &[u8]) -> Vec<u8> {
        match &self.sec {
            Some(sec) => sec
                .decrypt_string(num, self.gen_of(num), bytes)
                .unwrap_or_else(|| bytes.to_vec()),
            None => bytes.to_vec(),
        }
    }

    fn resolve_in_objstm(&self, num: u32, entry: XrefEntry, depth: usize) -> Option<PdfObject> {
        let stm = self.resolve_at(entry.f2 as u32, depth)?;
        let PdfObject::Stream { dict, raw } = stm else {
            return None;
        };
        let decoded = decode_stream_data(&dict, &raw)?;
        let n = PdfObject::dict_get(&dict, "N").and_then(|v| v.as_int())? as usize;
        let first = PdfObject::dict_get(&dict, "First").and_then(|v| v.as_int())? as usize;
        // The reservation is clamped to what the decoded stream can hold:
        // `N` is a field of the file, and a negative or huge one used to
        // buy the capacity before the header parse could refuse it.
        let mut l = Lexer {
            data: &decoded,
            pos: 0,
        };
        let mut slots: Vec<(u32, usize)> = Vec::with_capacity(n.min(decoded.len() / 3));
        for _ in 0..n {
            let onum = match l.next_tok() {
                Tok::Int(v) => v as u32,
                _ => break,
            };
            let off = match l.next_tok() {
                Tok::Int(v) if v >= 0 => v as usize,
                _ => break,
            };
            slots.push((onum, off));
        }
        for (onum, off) in slots {
            if onum == num {
                // checked: both halves are fields of the file, and a huge
                // pair must refuse the object rather than overflow the
                // position.
                let pos = first.checked_add(off)?;
                let mut ol = Lexer {
                    data: &decoded,
                    pos,
                };
                return parse_object(&mut ol, 0).ok();
            }
        }
        None
    }
}

fn merge_trailer(merged: &mut Vec<(String, PdfObject)>, trailer: Vec<(String, PdfObject)>) {
    // Sections are traversed newest → oldest, so the first value seen for a
    // key is the newest one: never overwrite an existing slot.
    for (k, v) in trailer {
        if merged.iter_mut().find(|(mk, _)| mk == &k).is_none() {
            merged.push((k, v));
        }
    }
}

// ---------------------------------------------------------------------------
// page tree
// ---------------------------------------------------------------------------

const MAX_PAGES: usize = 1_000_000;
const MAX_TREE_DEPTH: usize = 64;

impl PdfDocument<'_> {
    /// Collect `(page_dict, resources)` in document order by walking the
    /// page tree from the trailer's `/Root`, carrying inherited
    /// `/Resources` down the recursion.
    pub(crate) fn collect_pages(&self) -> Vec<(PdfObject, PdfObject)> {
        let mut pages = Vec::new();
        let Some(root_ref) = PdfObject::dict_get(&self.trailer, "Root") else {
            return pages;
        };
        let Some(root) = self.deref(root_ref) else {
            return pages;
        };
        let Some(root_dict) = root.as_dict() else {
            return pages;
        };
        let Some(pages_ref) = PdfObject::dict_get(root_dict, "Pages") else {
            return pages;
        };
        let mut visited: BTreeMap<u32, ()> = BTreeMap::new();
        self.walk_pages(pages_ref, None, 0, &mut visited, &mut pages);
        pages
    }

    fn walk_pages(
        &self,
        node_ref: &PdfObject,
        inherited: Option<&PdfObject>,
        depth: usize,
        visited: &mut BTreeMap<u32, ()>,
        pages: &mut Vec<(PdfObject, PdfObject)>,
    ) {
        if pages.len() >= MAX_PAGES || depth > MAX_TREE_DEPTH {
            return;
        }
        if let PdfObject::Ref(n, _) = node_ref {
            if visited.insert(*n, ()).is_some() {
                return; // cycle
            }
        }
        let Some(node) = self.deref(node_ref) else {
            return;
        };
        let Some(dict) = node.as_dict() else {
            return;
        };
        let resources = PdfObject::dict_get(dict, "Resources")
            .cloned()
            .or_else(|| inherited.cloned());
        let is_page = PdfObject::dict_get(dict, "Type")
            .and_then(|v| v.as_name())
            .is_some_and(|t| t == "Page")
            || (PdfObject::dict_get(dict, "Kids").is_none()
                && PdfObject::dict_get(dict, "Contents").is_some());
        if is_page {
            if let Some(res) = resources {
                pages.push((node.clone(), res));
            }
            return;
        }
        if let Some(PdfObject::Array(kids)) = PdfObject::dict_get(dict, "Kids") {
            for kid in kids {
                self.walk_pages(kid, resources.as_ref(), depth + 1, visited, pages);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// built-in encodings
// ---------------------------------------------------------------------------

/// WinAnsiEncoding patch over Latin-1 for 0x80..=0x9F (0 = undefined).
const WINANSI_HI: [u32; 32] = [
    0x20AC, 0, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039,
    0x0152, 0, 0x017D, 0, 0, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
    0x2122, 0x0161, 0x203A, 0x0153, 0, 0x017E, 0x0178,
];

/// MacRomanEncoding high half 0x80..=0xFF.
const MACROMAN_HI: [u32; 128] = [
    0x00C4, 0x00C5, 0x00C7, 0x00C9, 0x00D1, 0x00D6, 0x00DC, 0x00E1, 0x00E0, 0x00E2, 0x00E4, 0x00E3,
    0x00E5, 0x00E7, 0x00E9, 0x00E8, 0x00EA, 0x00EB, 0x00ED, 0x00EC, 0x00EE, 0x00EF, 0x00F1, 0x00F3,
    0x00F2, 0x00F4, 0x00F6, 0x00F5, 0x00FA, 0x00F9, 0x00FB, 0x00FC, 0x2020, 0x00B0, 0x00A2, 0x00A3,
    0x00A7, 0x2022, 0x00B6, 0x00DF, 0x00AE, 0x00A9, 0x2122, 0x00B4, 0x00A8, 0x2260, 0x00C6, 0x00D8,
    0x221E, 0x00B1, 0x2264, 0x2265, 0x00A5, 0x00B5, 0x2202, 0x2211, 0x220F, 0x03C0, 0x222B, 0x00AA,
    0x00BA, 0x03A9, 0x00E6, 0x00F8, 0x00BF, 0x00A1, 0x00AC, 0x221A, 0x0192, 0x2248, 0x2206, 0x00AB,
    0x00BB, 0x2026, 0x00A0, 0x00C0, 0x00C3, 0x00D5, 0x0152, 0x0153, 0x2013, 0x2014, 0x201C, 0x201D,
    0x2018, 0x2019, 0x00F7, 0x25CA, 0x00FF, 0x0178, 0x2044, 0x20AC, 0x2039, 0x203A, 0xFB01, 0xFB02,
    0x2021, 0x00B7, 0x201A, 0x201E, 0x2030, 0x00C2, 0x00CA, 0x00C1, 0x00CB, 0x00C8, 0x00CD, 0x00CE,
    0x00CF, 0x00CC, 0x00D3, 0x00D4, 0xF8FF, 0x00D2, 0x00DA, 0x00DB, 0x00D9, 0x0131, 0x02C6, 0x02DC,
    0x00AF, 0x02D8, 0x02D9, 0x02DA, 0x00B8, 0x02DD, 0x02DB, 0x02C7,
];

/// StandardEncoding, all 256 codes; 0 = undefined in this encoding
/// (PDF 32000-1 table D.2). Unlike WinAnsi this is *not* Latin-1 below
/// 0x80: 0x27 is `quoteright` and 0x60 is `quoteleft`, and the high half is
/// almost entirely holes.
///
/// The code→glyph-name list was cross-checked code for code against two
/// independent tables that agree on all 256 entries: pdf.js
/// `src/core/encodings.js` and the `C` codes of the URW `NimbusSans`
/// AFM (a Helvetica clone, so it is StandardEncoding). A third table was
/// consulted and rejected for MacRoman (below), where it disagrees with
/// this file's existing `MACROMAN_HI` in the repo's favour.
const STANDARD_ENC: [u32; 256] = [
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0020, 0x0021, 0x0022, 0x0023,
    0x0024, 0x0025, 0x0026, 0x2019, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B,
    0x003C, 0x003D, 0x003E, 0x003F, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
    0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F, 0x0050, 0x0051, 0x0052, 0x0053,
    0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    0x2018, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B,
    0x006C, 0x006D, 0x006E, 0x006F, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00A1, 0x00A2, 0x00A3, 0x2044, 0x00A5, 0x0192, 0x00A7,
    0x00A4, 0x0027, 0x201C, 0x00AB, 0x2039, 0x203A, 0xFB01, 0xFB02, 0x0000, 0x2013, 0x2020, 0x2021,
    0x00B7, 0x0000, 0x00B6, 0x2022, 0x201A, 0x201E, 0x201D, 0x00BB, 0x2026, 0x2030, 0x0000, 0x00BF,
    0x0000, 0x0060, 0x00B4, 0x02C6, 0x02DC, 0x00AF, 0x02D8, 0x02D9, 0x00A8, 0x0000, 0x02DA, 0x00B8,
    0x0000, 0x02DD, 0x02DB, 0x02C7, 0x2014, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x00C6, 0x0000, 0x00AA,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0141, 0x00D8, 0x0152, 0x00BA, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x00E6, 0x0000, 0x0000, 0x0000, 0x0131, 0x0000, 0x0000, 0x0142, 0x00F8, 0x0153, 0x00DF,
    0x0000, 0x0000, 0x0000, 0x0000,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BaseEncoding {
    WinAnsi,
    MacRoman,
    Standard,
}

impl BaseEncoding {
    fn decode(&self, byte: u8) -> Option<char> {
        match self {
            Self::WinAnsi => match byte {
                0x80..=0x9F => {
                    let cp = WINANSI_HI[(byte - 0x80) as usize];
                    if cp == 0 {
                        None
                    } else {
                        char::from_u32(cp)
                    }
                }
                _ => Some(byte as char), // Latin-1 range is identity
            },
            Self::MacRoman => match byte {
                0x00..=0x7F => Some(byte as char),
                _ => char::from_u32(MACROMAN_HI[(byte - 0x80) as usize]),
            },
            // StandardEncoding is not Latin-1: 0x27 is `quoteright` and
            // 0x60 is `quoteleft`, and most of 0x80..=0xFF is undefined.
            // Reading the whole table is the difference between the right
            // character and a plausible wrong one.
            Self::Standard => {
                let cp = STANDARD_ENC[byte as usize];
                if cp == 0 {
                    None
                } else {
                    char::from_u32(cp)
                }
            }
        }
    }
}

/// Adobe glyph name → char, covering the names that actually appear in
/// /Differences arrays (Latin text) plus uniXXXX.
fn glyph_to_char(name: &str) -> Option<char> {
    if name.len() == 1 {
        return name.chars().next();
    }
    if let Some(hex) = name.strip_prefix("uni") {
        if hex.len() == 4 {
            if let Ok(v) = u32::from_str_radix(hex, 16) {
                return char::from_u32(v);
            }
        }
        return None;
    }
    // algorithmic names: zero..nine, A-Z, a-z
    let c = match name {
        "zero" => '0',
        "one" => '1',
        "two" => '2',
        "three" => '3',
        "four" => '4',
        "five" => '5',
        "six" => '6',
        "seven" => '7',
        "eight" => '8',
        "nine" => '9',
        "space" => ' ',
        "exclam" => '!',
        "quotedbl" => '"',
        "numbersign" => '#',
        "dollar" => '$',
        "percent" => '%',
        "ampersand" => '&',
        "quotesingle" => '\'',
        "parenleft" => '(',
        "parenright" => ')',
        "asterisk" => '*',
        "plus" => '+',
        "comma" => ',',
        "hyphen" => '-',
        "period" => '.',
        "slash" => '/',
        "colon" => ':',
        "semicolon" => ';',
        "less" => '<',
        "equal" => '=',
        "greater" => '>',
        "question" => '?',
        "at" => '@',
        "bracketleft" => '[',
        "backslash" => '\\',
        "bracketright" => ']',
        "asciicircum" => '^',
        "underscore" => '_',
        "grave" => '`',
        "braceleft" => '{',
        "bar" => '|',
        "braceright" => '}',
        "asciitilde" => '~',
        "quotedblleft" => '\u{201C}',
        "quotedblright" => '\u{201D}',
        "quoteleft" => '\u{2018}',
        "quoteright" => '\u{2019}',
        "endash" => '\u{2013}',
        "emdash" => '\u{2014}',
        "bullet" => '\u{2022}',
        "fi" => '\u{FB01}',
        "fl" => '\u{FB02}',
        "ff" => '\u{FB00}',
        "ffi" => '\u{FB03}',
        "ffl" => '\u{FB04}',
        "degree" => '\u{00B0}',
        "minus" => '\u{2212}',
        "periodcentered" => '\u{00B7}',
        "dagger" => '\u{2020}',
        "daggerdbl" => '\u{2021}',
        "ellipsis" => '\u{2026}',
        "perthousand" => '\u{2030}',
        "guilsinglleft" => '\u{2039}',
        "guilsinglright" => '\u{203A}',
        "guillemotleft" => '\u{00AB}',
        "guillemotright" => '\u{00BB}',
        "florin" => '\u{0192}',
        "circumflex" => '\u{02C6}',
        "caron" => '\u{02C7}',
        "breve" => '\u{02D8}',
        "dotaccent" => '\u{02D9}',
        "ring" => '\u{02DA}',
        "ogonek" => '\u{02DB}',
        "tilde" => '\u{02DC}',
        "hungarumlaut" => '\u{02DD}',
        "commaaccent" => '\u{0326}',
        "cedilla" => '\u{00B8}',
        "acute" => '\u{00B4}',
        "dieresis" => '\u{00A8}',
        "macron" => '\u{00AF}',
        "section" => '\u{00A7}',
        "paragraph" => '\u{00B6}',
        "currency" => '\u{00A4}',
        "plusminus" => '\u{00B1}',
        "multiply" => '\u{00D7}',
        "divide" => '\u{00F7}',
        "logicalnot" => '\u{00AC}',
        "mu" => '\u{00B5}',
        "partialdiff" => '\u{2202}',
        "summation" => '\u{2211}',
        "product" => '\u{220F}',
        "radical" => '\u{221A}',
        "infinity" => '\u{221E}',
        "proportional" => '\u{221D}',
        "element" => '\u{2208}',
        "ae" => '\u{00E6}',
        "oslash" => '\u{00F8}',
        "adieresis" => '\u{00E4}',
        "agrave" => '\u{00E0}',
        "acircumflex" => '\u{00E2}',
        "atilde" => '\u{00E3}',
        "aring" => '\u{00E5}',
        "aacute" => '\u{00E1}',
        "ccedilla" => '\u{00E7}',
        "eacute" => '\u{00E9}',
        "egrave" => '\u{00E8}',
        "ecircumflex" => '\u{00EA}',
        "edieresis" => '\u{00EB}',
        "iacute" => '\u{00ED}',
        "igrave" => '\u{00EC}',
        "icircumflex" => '\u{00EE}',
        "idieresis" => '\u{00EF}',
        "ntilde" => '\u{00F1}',
        "oacute" => '\u{00F3}',
        "ograve" => '\u{00F2}',
        "ocircumflex" => '\u{00F4}',
        "odieresis" => '\u{00F6}',
        "otilde" => '\u{00F5}',
        "uacute" => '\u{00FA}',
        "ugrave" => '\u{00F9}',
        "ucircumflex" => '\u{00FB}',
        "udieresis" => '\u{00FC}',
        "yacute" => '\u{00FD}',
        "ydieresis" => '\u{00FF}',
        "scaron" => '\u{0161}',
        "zcaron" => '\u{017E}',
        "zacute" => '\u{017A}',
        "zdotaccent" => '\u{017C}',
        "cacute" => '\u{0107}',
        "ccaron" => '\u{010D}',
        "dcaron" => '\u{010F}',
        "ecaron" => '\u{011B}',
        "lacute" => '\u{013A}',
        "lcaron" => '\u{013E}',
        "nacute" => '\u{0144}',
        "ncaron" => '\u{0148}',
        "rcaron" => '\u{0159}',
        "racute" => '\u{0155}',
        "sacute" => '\u{015B}',
        "scedilla" => '\u{015F}',
        "scommaaccent" => '\u{0219}',
        "tcaron" => '\u{0165}',
        "tcommaaccent" => '\u{021B}',
        "udoubleacute" => '\u{0171}',
        "umacron" => '\u{016B}',
        "uogonek" => '\u{0173}',
        "germandbls" => '\u{00DF}',
        "Adieresis" => '\u{00C4}',
        "Agrave" => '\u{00C0}',
        "Acircumflex" => '\u{00C2}',
        "Atilde" => '\u{00C3}',
        "Aring" => '\u{00C5}',
        "Aacute" => '\u{00C1}',
        "Ccedilla" => '\u{00C7}',
        "Eacute" => '\u{00C9}',
        "Egrave" => '\u{00C8}',
        "Ecircumflex" => '\u{00CA}',
        "Edieresis" => '\u{00CB}',
        "Iacute" => '\u{00CD}',
        "Igrave" => '\u{00CC}',
        "Icircumflex" => '\u{00CE}',
        "Idieresis" => '\u{00CF}',
        "Ntilde" => '\u{00D1}',
        "Oacute" => '\u{00D3}',
        "Ograve" => '\u{00D2}',
        "Ocircumflex" => '\u{00D4}',
        "Odieresis" => '\u{00D6}',
        "Otilde" => '\u{00D5}',
        "Uacute" => '\u{00DA}',
        "Ugrave" => '\u{00D9}',
        "Ucircumflex" => '\u{00DB}',
        "Udieresis" => '\u{00DC}',
        "Yacute" => '\u{00DD}',
        "Ydieresis" => '\u{0178}',
        "Scaron" => '\u{0160}',
        "Zcaron" => '\u{017D}',
        "Zacute" => '\u{0179}',
        "Zdotaccent" => '\u{017B}',
        "AE" => '\u{00C6}',
        "Oslash" => '\u{00D8}',
        "Lslash" => '\u{0141}',
        "lslash" => '\u{0142}',
        "Eth" => '\u{00D0}',
        "eth" => '\u{00F0}',
        "Thorn" => '\u{00DE}',
        "thorn" => '\u{00FE}',
        "dotlessi" => '\u{0131}',
        _ => return None,
    };
    Some(c)
}

// ---------------------------------------------------------------------------
// ToUnicode CMap
// ---------------------------------------------------------------------------

/// A parsed ToUnicode CMap: code (big-endian value) → unicode text.
#[derive(Debug, Clone, Default)]
struct CMap {
    map: BTreeMap<u32, String>,
    code_len: usize, // bytes per code from the codespace range (default 1)
}

impl CMap {
    fn parse(data: &[u8]) -> CMap {
        let mut cmap = CMap {
            map: BTreeMap::new(),
            code_len: 1,
        };
        let mut pos = 0usize;
        let mut state = ScanState::Top;
        while pos < data.len() {
            skip_ws_at(data, &mut pos);
            if pos >= data.len() {
                break;
            }
            match data[pos] {
                b'<' if data.get(pos + 1) != Some(&b'<') => {
                    // hex string token
                    let (bytes, np) = scan_hex_tok(data, pos);
                    pos = np;
                    match state {
                        ScanState::CodeSpace => {
                            // pairs; first pair's src length = code length
                            cmap.code_len = cmap.code_len.max(bytes.len().min(4));
                        }
                        // the source code is unused: the code length comes from
                        // `bytes`, and for a bfrange the first token is the
                        // low bound, handled by the BfRange arm
                        ScanState::BfChar(_src) => {
                            state = ScanState::BfCharDst(bytes);
                        }
                        ScanState::BfCharDst(src) => {
                            cmap.map.insert(be_value(&src), dst_to_string(&bytes));
                            state = ScanState::BfChar(None);
                        }
                        ScanState::BfRange(None) => {
                            // first hex token of a range is the low bound
                            state = ScanState::BfRangeHi(bytes);
                        }
                        ScanState::BfRangeHi(lo) => {
                            state = ScanState::BfRangeDst { lo, hi: bytes };
                        }
                        ScanState::BfRangeDst { lo, hi } => {
                            // array form handled below via '[' token
                            cmap.insert_range(&lo, &hi, &bytes, 0);
                            state = ScanState::BfRange(None);
                        }
                        ScanState::BfRangeArray { lo, idx } => {
                            cmap.insert_range(&lo, &lo, &bytes, idx);
                            state = ScanState::BfRangeArray { lo, idx: idx + 1 };
                        }
                        _ => {}
                    }
                }
                b'[' => {
                    pos += 1;
                    if let ScanState::BfRangeDst { lo, hi: _ } = state {
                        state = ScanState::BfRangeArray { lo, idx: 0 };
                    }
                }
                b']' => {
                    pos += 1;
                    if matches!(state, ScanState::BfRangeArray { .. }) {
                        state = ScanState::BfRange(None);
                    }
                }
                _ => {
                    // word token
                    let start = pos;
                    while pos < data.len() && !is_ws(data[pos]) && data[pos] != b'<' {
                        pos += 1;
                    }
                    if pos == start {
                        pos += 1; // stray '<' (e.g. '<<' dict open): never stall
                        continue;
                    }
                    let word = &data[start..pos];
                    match word {
                        b"begincodespacerange" => state = ScanState::CodeSpace,
                        b"endcodespacerange" => state = ScanState::Top,
                        b"beginbfchar" => state = ScanState::BfChar(None),
                        b"endbfchar" => state = ScanState::Top,
                        b"beginbfrange" => state = ScanState::BfRange(None),
                        b"endbfrange" => state = ScanState::Top,
                        _ => {}
                    }
                }
            }
        }
        cmap
    }

    fn insert_range(&mut self, lo: &[u8], hi: &[u8], dst: &[u8], idx: u32) {
        const MAX_CMAP_ENTRIES: usize = 1 << 20;
        let lo_v = be_value(lo);
        let hi_v = be_value(hi);
        let count = hi_v.saturating_sub(lo_v).min(65535);
        // The budget is the map's, not the range's: a small ToUnicode
        // stream of maximal `<lo> <ffff>` ranges used to insert tens of
        // thousands of entries each, and a megabyte of them was billions
        // of strings. A real CMap maps its glyphs once.
        let budget = MAX_CMAP_ENTRIES.saturating_sub(self.map.len());
        for k in 0..=count {
            if (k as usize) >= budget {
                return;
            }
            let mut d = dst.to_vec();
            // increment dst as a big-endian number by (idx + k)
            add_be(&mut d, idx + k);
            self.map.insert(lo_v + k, dst_to_string(&d));
        }
    }
}

#[derive(Debug, Clone)]
enum ScanState {
    Top,
    CodeSpace,
    BfChar(Option<Vec<u8>>),
    BfCharDst(Vec<u8>),
    BfRangeHi(Vec<u8>),
    BfRangeDst { lo: Vec<u8>, hi: Vec<u8> },
    BfRangeArray { lo: Vec<u8>, idx: u32 },
    BfRange(Option<Vec<u8>>),
}

fn scan_hex_tok(data: &[u8], pos: usize) -> (Vec<u8>, usize) {
    let mut nibbles = Vec::new();
    let mut p = pos + 1; // consume '<'
    while p < data.len() && data[p] != b'>' {
        if let Some(v) = hex_val(data[p]) {
            nibbles.push(v);
        }
        p += 1;
    }
    if p < data.len() {
        p += 1; // consume '>'
    }
    if nibbles.len() % 2 == 1 {
        nibbles.push(0);
    }
    let bytes: Vec<u8> = nibbles
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| (c[0] << 4) | c[1])
        .collect();
    (bytes, p)
}

fn be_value(bytes: &[u8]) -> u32 {
    let mut v: u32 = 0;
    for &b in bytes.iter().take(4) {
        v = (v << 8) | b as u32;
    }
    v
}

fn add_be(bytes: &mut [u8], n: u32) {
    let mut carry = n;
    for b in bytes.iter_mut().rev() {
        let s = *b as u32 + (carry & 0xFF);
        *b = s as u8;
        carry = (carry >> 8) + (s >> 8);
    }
}

/// CMap destination bytes: UTF-16BE when even-length, else Latin-1-ish.
fn dst_to_string(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.len().is_multiple_of(2) {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

// ---------------------------------------------------------------------------
// font decoder
// ---------------------------------------------------------------------------

/// How a font's codes can be turned into characters, decided once per font
/// rather than per byte so that the per-byte path stays a table walk.
///
/// The `Undecodable` arm exists because the alternative is a wrong answer.
/// Every shortcut that reaches for a glyph index when there is no mapping —
/// the Latin-1 fallback this crate used to take, `Identity` on a composite
/// font's CIDs — turns an undecodable glyph into a *confident* wrong
/// character, and a search that silently returns the wrong line is worse
/// than one that says the line was never decoded. rgx's own rule is the
/// same one `rgx_core::process` applies to a failing adapter: a file that
/// cannot be read is still accounted for, by a searchable note, rather than
/// vanishing or lying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FontSource {
    /// A `/ToUnicode` CMap covers the font's codes.
    CMap,
    /// The codes are character codes under `/Differences` and/or a base
    /// encoding this reader knows.
    Encoding,
    /// The codes name glyphs whose characters live in the embedded font
    /// program, which would take a Type 1 / TrueType / CFF parser. The
    /// payload is why, and it goes into the document's note verbatim.
    Undecodable(&'static str),
}

#[derive(Debug, Clone)]
struct FontDecoder {
    /// Direct lookup table for single-byte fonts (256 entries, no
    /// tree walk). Two-byte (CID / Type 0) fonts keep the BTreeMap
    /// because their code-point space can exceed 8 bits and the
    /// density of populated entries is usually lower than 50%.
    cmap: CMapLookup,
    diffs: BTreeMap<u8, char>,
    base: Option<BaseEncoding>,
    source: FontSource,
}

#[derive(Debug, Clone)]
enum CMapLookup {
    /// 256-entry table for 1-byte fonts. Boxed so the OneByte arm doesn't
    /// bloat every other variant: 256 * (size of Option<String>) is 6 KiB,
    /// and the enum is held by value in `FontDecoder` so leaving it inline
    /// made the decoder ~24x larger than it needed to be.
    OneByte(Box<[Option<String>; 256]>),
    /// u32 -> String for multi-byte fonts (CIDs, identity mappings).
    ManyByte(BTreeMap<u32, String>),
}

impl FontDecoder {
    fn build(doc: &PdfDocument<'_>, font_dict: &[(String, PdfObject)]) -> FontDecoder {
        let subtype = PdfObject::dict_get(font_dict, "Subtype")
            .and_then(|v| v.as_name())
            .unwrap_or("");
        let two_byte = subtype == "Type0";

        // ToUnicode CMap
        let mut cmap_table: BTreeMap<u32, String> = BTreeMap::new();
        if let Some(tu) = PdfObject::dict_get(font_dict, "ToUnicode") {
            if let Some(decoded) = doc.decode_stream(tu) {
                cmap_table = CMap::parse(&decoded).map;
            }
        }
        // For 1-byte fonts (which dominate the corpus), a 256-entry
        // Option<String> table turns each glyph decode into one
        // array access instead of a BTreeMap walk. The two-byte
        // branch keeps the BTreeMap because its code-point space is
        // sparser and a 65536-entry table wastes memory.
        let cmap = if two_byte {
            CMapLookup::ManyByte(cmap_table)
        } else {
            let mut t: [Option<String>; 256] = [const { None }; 256];
            for (k, v) in cmap_table {
                let slot = (k as usize) & 0xFF;
                if t[slot].is_none() {
                    t[slot] = Some(v);
                }
            }
            CMapLookup::OneByte(Box::new(t))
        };

        // simple-font /Encoding: BaseEncoding + Differences
        let mut diffs: BTreeMap<u8, char> = BTreeMap::new();
        let mut base: Option<BaseEncoding> = None;
        let mut encoding_declared = false;
        let mut unknown_encoding = false;
        if !two_byte {
            if let Some(enc) = PdfObject::dict_get(font_dict, "Encoding") {
                encoding_declared = true;
                let resolved = doc.deref(enc);
                if let Some(PdfObject::Dict(enc_dict)) = &resolved {
                    let declared =
                        PdfObject::dict_get(enc_dict, "BaseEncoding").and_then(|v| v.as_name());
                    base = declared.and_then(base_encoding_of);
                    unknown_encoding = declared.is_some() && base.is_none();
                    if let Some(PdfObject::Array(d)) = PdfObject::dict_get(enc_dict, "Differences")
                    {
                        let mut code: i64 = 0;
                        for item in d {
                            match item.as_int() {
                                Some(c) => code = c,
                                None => {
                                    if let Some(name) = item.as_name() {
                                        if let Some(ch) = glyph_to_char(name) {
                                            diffs.insert(code as u8, ch);
                                        }
                                        code += 1;
                                    }
                                }
                            }
                        }
                    }
                } else if let Some(name) = resolved.as_ref().and_then(|e| e.as_name()) {
                    base = base_encoding_of(name);
                    unknown_encoding = base.is_none();
                }
            } else {
                // No /Encoding: the base encoding is the font's own
                // (PDF 32000-1 9.2.4). StandardEncoding for a non-symbolic
                // Type 1 — the base-14 default, and what a LaTeX-emitted
                // subset of a text font is subset as; WinAnsiEncoding for a
                // non-symbolic TrueType; and the font program's own built-in
                // encoding for a symbolic font or a Type 3, which this crate
                // has no parser for and so does not guess at.
                let symbolic = doc
                    .deref(
                        PdfObject::dict_get(font_dict, "FontDescriptor")
                            .unwrap_or(&PdfObject::Null),
                    )
                    .and_then(|fd| fd.as_dict().map(<[(String, PdfObject)]>::to_vec))
                    .and_then(|fd| PdfObject::dict_get(&fd, "Flags").and_then(|v| v.as_int()))
                    .is_some_and(|flags| flags & 4 != 0);
                base = match (symbolic, subtype) {
                    (false, "Type1") => Some(BaseEncoding::Standard),
                    (false, "TrueType") => Some(BaseEncoding::WinAnsi),
                    _ => None,
                };
            }
        }

        let cmap_is_empty = match &cmap {
            CMapLookup::OneByte(t) => t.iter().all(|o| o.is_none()),
            CMapLookup::ManyByte(m) => m.is_empty(),
        };
        let source = if !cmap_is_empty {
            FontSource::CMap
        } else if !diffs.is_empty() || base.is_some() {
            FontSource::Encoding
        } else if two_byte {
            FontSource::Undecodable("composite font with no /ToUnicode CMap")
        } else if unknown_encoding {
            FontSource::Undecodable("/Encoding names an encoding this reader does not know")
        } else if encoding_declared {
            FontSource::Undecodable("/Encoding /Differences names only glyphs with no Unicode")
        } else {
            FontSource::Undecodable("symbolic font whose encoding lives in the font program")
        };

        FontDecoder {
            cmap,
            diffs,
            base,
            source,
        }
    }

    fn decode(&self, bytes: &[u8]) -> String {
        let mut out = String::new();
        match &self.cmap {
            CMapLookup::ManyByte(map) => {
                for chunk in bytes.as_chunks::<2>().0 {
                    let code = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
                    if let Some(s) = map.get(&code) {
                        out.push_str(s);
                    }
                    // A CID with no CMap entry is not a Unicode scalar
                    // value; dropping it (and naming it in the document
                    // note) is what stops U+0003 from sneaking into the
                    // corpus as a "binary" hit.
                }
            }
            CMapLookup::OneByte(table) => {
                for &b in bytes {
                    if let Some(s) = table[b as usize].as_ref() {
                        out.push_str(s);
                    } else if let Some(&c) = self.diffs.get(&b) {
                        out.push(c);
                    } else if let Some(base) = self.base {
                        if let Some(c) = base.decode(b) {
                            out.push(c);
                        }
                    }
                    // else: dropped, same as above.
                }
            }
        }
        out
    }
}

fn base_encoding_of(name: &str) -> Option<BaseEncoding> {
    match name {
        "WinAnsiEncoding" => Some(BaseEncoding::WinAnsi),
        "MacRomanEncoding" => Some(BaseEncoding::MacRoman),
        "StandardEncoding" | "PDFDocEncoding" => Some(BaseEncoding::Standard),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// content stream → text (font-aware tokenizer)
// ---------------------------------------------------------------------------

enum CTok<'a> {
    Str(Vec<u8>),
    Num(f32),
    Name(String),
    Op(&'a str),
}

/// Tokenize a content stream into operands/operators.
///
/// The bytes arrive already decrypted: a content stream is a single object
/// encrypted as a whole, so the `(…)` literals lifted out of it are
/// plaintext. Running them back through the cipher is the classic way to
/// turn a correctly-decrypted page into noise.
fn content_tokens<'a>(content: &'a [u8]) -> Vec<CTok<'a>> {
    let mut toks = Vec::new();
    let mut i = 0usize;
    let n = content.len();
    while i < n {
        let c = content[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' | 0 | 0x0C => i += 1,
            b'%' => {
                while i < n && content[i] != b'\n' && content[i] != b'\r' {
                    i += 1;
                }
            }
            b'(' => {
                let mut l = Lexer {
                    data: content,
                    pos: i,
                };
                let s = l.read_literal_string();
                toks.push(CTok::Str(s));
                i = l.pos;
            }
            b'<' => {
                if content.get(i + 1) == Some(&b'<') {
                    // inline dict: skip to matching >>
                    let mut depth = 0i32;
                    let mut j = i;
                    while j + 1 < n {
                        if content[j] == b'<' && content[j + 1] == b'<' {
                            depth += 1;
                            j += 2;
                        } else if content[j] == b'>' && content[j + 1] == b'>' {
                            depth -= 1;
                            j += 2;
                            if depth == 0 {
                                break;
                            }
                        } else {
                            j += 1;
                        }
                    }
                    i = j;
                } else {
                    let mut l = Lexer {
                        data: content,
                        pos: i,
                    };
                    let s = l.read_hex_string();
                    toks.push(CTok::Str(s));
                    i = l.pos;
                }
            }
            b'/' => {
                let mut l = Lexer {
                    data: content,
                    pos: i + 1,
                };
                let name = l.read_name();
                toks.push(CTok::Name(name));
                i = l.pos;
            }
            b'[' | b']' => {
                toks.push(CTok::Op(if c == b'[' { "[" } else { "]" }));
                i += 1;
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < n && (content[i].is_ascii_digit() || content[i] == b'.') {
                    i += 1;
                }
                if let Ok(v) = str::from_utf8(&content[start..i])
                    .unwrap_or("")
                    .parse::<f32>()
                {
                    toks.push(CTok::Num(v));
                }
            }
            _ => {
                let start = i;
                while i < n
                    && (content[i].is_ascii_alphabetic()
                        || matches!(content[i], b'*' | b'\'' | b'"'))
                {
                    i += 1;
                }
                if i == start {
                    i += 1;
                    continue;
                }
                let op = str::from_utf8(&content[start..i]).unwrap_or("");
                toks.push(CTok::Op(op));
            }
        }
    }
    toks
}

/// The text runs of one page, counted by how they were painted.
///
/// The rendering mode is part of the text state, which the page
/// initialises, so a page's mode starts at 0 -- fill, the visible one --
/// and only a `Tr` operator moves it.
///
/// A **run** is one text-showing OPERATOR (`Tj`, `TJ`, `'` or `"`) that
/// carried a string. The three strings of one `TJ` array are one run,
/// because the array is one show operation: a note that counted the
/// strings would report a number the page does not have, and the count
/// exists to be compared with the number of operations a reader can
/// point at.
#[derive(Debug, Default, Clone, Copy)]
struct PageRuns {
    /// Text-showing operators that carried a string.
    total: usize,
    /// The ones drawn in a mode that paints nothing.
    invisible: usize,
    /// The invisible ones that put at least one character in the text.
    invisible_text: usize,
}

impl PageRuns {
    /// Count one text-showing operation, and whether it put anything in
    /// the text.
    fn note(&mut self, mode: i32, put_text: bool) {
        self.total += 1;
        if !mode_paints(mode) {
            self.invisible += 1;
            if put_text {
                self.invisible_text += 1;
            }
        }
    }
}

/// Whether a rendering mode puts ink on the page.
///
/// `3 Tr` and `7 Tr` are the two modes that neither fill nor stroke the
/// glyphs: the text is positioned and measured, and nothing is painted.
/// A producer lays a text layer over a scan with them, so the page reads
/// as a picture while the text is still in the file -- which is why the
/// reader has to know the mode was there at all.
fn mode_paints(mode: i32) -> bool {
    !matches!(mode, 3 | 7)
}

/// Extract text from one page's decoded content stream using the page's
/// fonts. Returns how many shown strings named a font `/Resources` did not
/// define.
fn extract_content_text(
    content: &[u8],
    fonts: &BTreeMap<String, FontDecoder>,
    out: &mut String,
    runs: &mut PageRuns,
) -> usize {
    let mut cur_font: Option<&FontDecoder> = None;
    let mut shown = false;
    // Whether a glyph has been shown since the last line break. A number in
    // a `TJ` array is the adjustment between the glyph shown last and the
    // one shown next, and those two are routinely in *different* arrays:
    // pdfTeX closes a run whenever the typeface changes, so
    // `[(formalise)-249(the)]TJ /F2 Tf [-249(T)92(esla)]TJ` puts the word
    // space at the head of the second array. Requiring a string to have
    // been seen in the *same* array lost it, and the paper came out as
    // "theTesla". Reset on a line break, because a new line is a new line.
    extract_one(
        content_tokens(content),
        &mut cur_font,
        &mut shown,
        fonts,
        out,
        runs,
    )
}

/// The token walk proper, kept separate so the caller above reads as a
/// statement of what it does rather than a hundred lines of nesting.
fn extract_one<'f>(
    toks: Vec<CTok<'_>>,
    cur_font: &mut Option<&'f FontDecoder>,
    shown: &mut bool,
    fonts: &'f BTreeMap<String, FontDecoder>,
    out: &mut String,
    runs: &mut PageRuns,
) -> usize {
    let mut operands: Vec<&CTok<'_>> = Vec::new();
    let mut missing = 0usize;
    // The text rendering mode, part of the text state: `Tr` sets it and
    // it stays set until another `Tr` says otherwise. `BT`/`ET` open and
    // close a text OBJECT, not the text state, so they do not reset it,
    // and the state itself is initialised with the page -- so the mode
    // starts at 0, the visible one, for every page.
    let mut render_mode: i32 = 0;
    for t in &toks {
        match t {
            CTok::Op(op) => {
                // `[` and `]` group operands; they are not operators. Clearing
                // the operand stack on them made every array-form text-showing
                // operator a no-op, and `TJ` is the only form pdfTeX emits:
                // `[(At)-252(the)-251(scanning)]TJ` reached `TJ` with an
                // already-emptied stack and printed nothing.
                if *op == "[" || *op == "]" {
                    continue;
                }
                match *op {
                    "Tf" => {
                        // "/F1 12 Tf" → set current font
                        if let Some(CTok::Name(name)) =
                            operands.iter().rev().find(|o| matches!(o, CTok::Name(_)))
                        {
                            *cur_font = fonts.get(name.as_str());
                            if cur_font.is_none() {
                                missing += 1;
                            }
                        }
                    }
                    "Tr" => {
                        // "3 Tr" → the glyphs are positioned and measured
                        // but no ink goes on the page. The mode is kept
                        // because the page looks different from one drawn
                        // with `0 Tr`, and the reader has to be able to
                        // say so.
                        if let Some(CTok::Num(v)) = operands.last() {
                            render_mode = *v as i32;
                        }
                    }
                    "Tj" => {
                        if let Some(CTok::Str(b)) = operands.last() {
                            let put = show_string(b, *cur_font, out);
                            *shown = true;
                            runs.note(render_mode, put);
                        }
                    }
                    "'" | "\"" => {
                        out.push('\n');
                        *shown = false;
                        if let Some(CTok::Str(b)) = operands.last() {
                            let put = show_string(b, *cur_font, out);
                            *shown = true;
                            runs.note(render_mode, put);
                        }
                    }
                    "TJ" => {
                        // array: strings with kerning numbers between them
                        let mut put = false;
                        for o in operands.iter() {
                            match o {
                                CTok::Str(b) => {
                                    put |= show_string(b, *cur_font, out);
                                    *shown = true;
                                }
                                CTok::Num(v) if *v <= -120.0 && *shown => {
                                    out.push(' ');
                                }
                                _ => {}
                            }
                        }
                        // One run for the whole array: the operator is one
                        // show operation, whatever the array holds. A run is
                        // counted when the array carried a string at all,
                        // even when the string decoded to nothing -- the
                        // producer drew text there, and that is the fact the
                        // note is about.
                        if operands.iter().any(|o| matches!(o, CTok::Str(_))) {
                            runs.note(render_mode, put);
                        }
                    }
                    "Td" | "TD" => {
                        // moving down = new line; moving right = word gap
                        let nums: Vec<f32> = operands
                            .iter()
                            .filter_map(|o| match o {
                                CTok::Num(v) => Some(*v),
                                _ => None,
                            })
                            .collect();
                        if let [tx, ty] = nums[..] {
                            if ty.abs() > 1.0 {
                                out.push('\n');
                                *shown = false;
                            } else if tx.abs() > 1.0 {
                                out.push(' ');
                            }
                        } else {
                            out.push('\n');
                            *shown = false;
                        }
                    }
                    "T*" | "BT" | "ET" | "Tm" => {
                        out.push('\n');
                        *shown = false;
                    }
                    _ => {}
                }
                operands.clear();
            }
            _ => operands.push(t),
        }
    }
    missing
}

/// Show one string. A `None` font means the content stream selected a font
/// the page's `/Resources` did not define: the bytes are character codes of
/// an encoding nobody named, so they are dropped rather than read as
/// Latin-1, and `extract_content_text` counts the selection for the report.
///
/// Returns whether anything at all reached the text, so the caller can tell
/// a run that made it into the output from one that decoded to nothing.
fn show_string(bytes: &[u8], font: Option<&FontDecoder>, out: &mut String) -> bool {
    match font {
        Some(f) => {
            let decoded = f.decode(bytes);
            let put = !decoded.is_empty();
            out.push_str(&decoded);
            put
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/// Entry point mirroring the other binary-format readers.
pub struct PdfReader;

impl PdfReader {
    pub fn parse(data: &[u8]) -> PdfResult<PdfDocument<'_>> {
        PdfDocument::parse(data)
    }
}

const MAX_EXTRACT: usize = 64 << 20; // total text across all pages

/// What a page's fonts could and could not contribute, accumulated across
/// the document so that a font repeated on twelve pages is named once.
#[derive(Debug, Default, Clone)]
pub struct FontReport {
    /// (reason, number of fonts) in first-seen order.
    pub undecodable: Vec<(&'static str, usize)>,
    /// `/F…` names a content stream selected that `/Resources` did not
    /// define; their strings are dropped rather than guessed at.
    pub missing: usize,
}

impl FontReport {
    fn note_font(&mut self, source: FontSource) {
        if let FontSource::Undecodable(why) = source {
            match self.undecodable.iter_mut().find(|(r, _)| *r == why) {
                Some((_, n)) => *n += 1,
                None => self.undecodable.push((why, 1)),
            }
        }
    }
}

/// How the document's text was painted, counted over the whole file.
///
/// The rendering mode is not decoration: text drawn with `3 Tr` is not on
/// the page, so a reader that answers the same for a page drawn with
/// `0 Tr` and the same page drawn with `3 Tr` cannot tell a text page
/// from a blank one. The count is what lets the adapter say which of the
/// two it found.
#[derive(Debug, Default, Clone)]
pub struct RunReport {
    /// Text-showing operators that carried a string, over the document.
    pub total: usize,
    /// The ones drawn in a mode that paints nothing.
    pub invisible: usize,
    /// The invisible ones that put at least one character in the text.
    pub invisible_text: usize,
    /// Pages that carried at least one invisible run.
    pub pages_with_invisible: usize,
}

impl RunReport {
    /// True when at least one text run was drawn in a mode that paints
    /// nothing.
    pub fn has_invisible(&self) -> bool {
        self.invisible > 0
    }

    /// True when the document's whole text layer is invisible: every
    /// text-showing operation happened in a mode that paints nothing, so
    /// the pages show no text at all and what the file holds is a picture
    /// with words under it.
    pub fn is_entirely_invisible(&self) -> bool {
        self.total > 0 && self.invisible == self.total
    }
}

/// A document's text plus the fonts that text had to leave out. The note is
/// data, not a rendered string, so that the adapter owns the wording — the
/// same split `metadata()` leaves to `lib.rs`.
#[derive(Debug, Default, Clone)]
pub struct Extraction {
    pub text: String,
    /// (reason, number of fonts) for fonts whose codes could not be turned
    /// into characters without parsing the embedded font program.
    pub undecodable: Vec<(&'static str, usize)>,
    /// Font names the content stream selected that `/Resources` did not
    /// define.
    pub missing_fonts: usize,
    /// Pages walked. The undecodable count is per page — a font used on
    /// twelve pages is counted twelve times, because that is how many times
    /// it was left out of the text — so the note has to say which it is.
    pub pages: usize,
    /// How the text was painted.
    pub runs: RunReport,
}

impl Extraction {
    /// True when some font contributed nothing and the reader can say why.
    pub fn is_partial(&self) -> bool {
        !self.undecodable.is_empty() || self.missing_fonts > 0
    }

    /// True when at least one text run was drawn in a mode that paints
    /// nothing.
    pub fn has_invisible_runs(&self) -> bool {
        self.runs.has_invisible()
    }

    /// True when the document's whole text layer is invisible: every
    /// text-showing operation happened in a mode that paints nothing, so
    /// the pages show no text at all and what the file holds is a picture
    /// with words under it.
    pub fn is_entirely_invisible(&self) -> bool {
        self.runs.is_entirely_invisible()
    }
}

impl PdfDocument<'_> {
    /// Number of pages in the page tree.
    pub fn page_count(&self) -> usize {
        self.collect_pages().len()
    }

    /// Decoded text of one page (0-based). None when out of range or the
    /// page has no decodable content stream.
    ///
    /// `report` accumulates rather than being returned, so that a caller
    /// walking twelve pages can name a font once instead of twelve times,
    /// and so that a caller reading one page cannot forget to look.
    ///
    /// The plain form is the one a single page is read with; the walk
    /// over a whole document wants the rendering modes of the text as
    /// well, and gets them from `page_text_with_runs`. Without the
    /// attribute, `cargo clippy --all-targets` flags this one as dead in
    /// the lib-only build.
    #[allow(dead_code)]
    pub fn page_text(&self, idx: usize, report: &mut FontReport) -> Option<String> {
        self.page_text_with_runs(idx, report, &mut RunReport::default())
    }

    /// One page's text, and how that text was painted.
    ///
    /// The rendering modes are counted here, inside the one walk over the
    /// content stream, because the mode is part of the text state: it is
    /// only known while the stream is being read, and a second pass would
    /// have to walk it again to learn the same thing.
    pub fn page_text_with_runs(
        &self,
        idx: usize,
        report: &mut FontReport,
        runs: &mut RunReport,
    ) -> Option<String> {
        let pages = self.collect_pages();
        let (page, resources) = pages.get(idx)?;
        let dict = page.as_dict()?;
        let contents = PdfObject::dict_get(dict, "Contents")?;
        // Each element of an array `/Contents` is decrypted under its own
        // object key, so the streams are decoded one at a time and only
        // then joined. Joining first would apply a single key to bytes
        // belonging to several objects.
        let mut content = Vec::new();
        match contents {
            PdfObject::Array(items) => {
                for item in items {
                    self.push_stream_bytes(item, &mut content);
                }
            }
            other => self.push_stream_bytes(other, &mut content),
        }
        if content.is_empty() {
            return None;
        }
        let fonts = self.font_decoders(resources);
        for f in fonts.values() {
            report.note_font(f.source);
        }
        let mut out = String::new();
        let mut page_runs = PageRuns::default();
        report.missing += extract_content_text(&content, &fonts, &mut out, &mut page_runs);
        // The page counters are folded in before the emptiness check: a
        // page whose text decoded to nothing still ran its text-showing
        // operators, and a run that painted nothing is the fact the note
        // is about.
        runs.total += page_runs.total;
        runs.invisible += page_runs.invisible;
        runs.invisible_text += page_runs.invisible_text;
        if page_runs.invisible > 0 {
            runs.pages_with_invisible += 1;
        }
        if out.trim().is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// The images drawn on one page.
    ///
    /// Only `/DCTDecode` images come back as something an OCR engine can be
    /// handed: that filter *is* JPEG, so the stored bytes already are an
    /// image and undoing it would destroy it. Everything else is reported
    /// with the filter that keeps it compressed rather than dropped — a
    /// scanned page whose only image is CCITT G4 is a real answer, and
    /// silence would read as "this page has no images".
    pub fn page_images(&self, idx: usize) -> Vec<PageImage> {
        let pages = self.collect_pages();
        let Some((_, resources)) = pages.get(idx) else {
            return Vec::new();
        };
        let Some(res) = self
            .deref(resources)
            .and_then(|r| r.as_dict().map(<[(String, PdfObject)]>::to_vec))
        else {
            return Vec::new();
        };
        let Some(xobjects) = PdfObject::dict_get(&res, "XObject").and_then(|x| self.deref(x))
        else {
            return Vec::new();
        };
        let Some(dict) = xobjects.as_dict() else {
            return Vec::new();
        };

        let mut out = Vec::new();
        for (_name, obj) in dict {
            let Some(PdfObject::Stream { dict: sdict, raw }) = self.deref(obj) else {
                continue;
            };
            let is_image = matches!(
                PdfObject::dict_get(&sdict, "Subtype"),
                Some(PdfObject::Name(n)) if n.as_str() == "Image"
            );
            if !is_image {
                continue;
            }
            // An image is encrypted like any other stream, so a JPEG handed
            // to an OCR engine from an encrypted document has to come out of
            // the cipher first — handing over the ciphertext produces a
            // recogniser failure that looks like a bad scan.
            let raw = match self.stream_ciphertext(obj, &raw) {
                Some(p) => p,
                None => continue,
            };
            let filter = stream_filter_name(&sdict);
            let width = dict_int(&sdict, "Width").unwrap_or(0) as u32;
            let height = dict_int(&sdict, "Height").unwrap_or(0) as u32;
            let bits = dict_int(&sdict, "BitsPerComponent").unwrap_or(8) as u8;

            let mut jpeg = None;
            let mut png = None;
            match filter.as_str() {
                // The filter *is* JPEG; the stored bytes already are the
                // image, and undoing it would destroy it.
                "DCTDecode" | "DCT" => jpeg = Some(raw),
                // A fax scan is not an image until it is decoded. Left as
                // bytes it is a bitstream a recogniser cannot read, which is
                // why this used to be a filter name in a note and now is a
                // page.
                "CCITTFaxDecode" | "CCF" => {
                    let parms = sdict
                        .iter()
                        .find(|(k, _)| k == "DecodeParms" || k == "DP")
                        .and_then(|(_, v)| v.as_dict())
                        .map(parms_from_dict)
                        .unwrap_or_default();
                    png = decode_fax_png(&raw, &parms, width, height);
                }
                // A JBIG2 page is a program against a template and a
                // dictionary of glyphs, not a picture either. The size comes
                // from the image dictionary — a PDF's JBIG2 stream has no
                // page information segment of its own — and the glyph
                // dictionary, when there is one, comes from `/JBIG2Globals`.
                "JBIG2Decode" | "JBIG2" => {
                    let globals = self.jbig2_globals(&sdict);
                    png = decode_jbig2_png(globals.as_deref(), &raw, width, height);
                }
                _ => {}
            }
            out.push(PageImage {
                width,
                height,
                bits,
                filter,
                jpeg,
                png,
            });
        }
        out
    }

    /// Every page's images, flattened. A caller OCRing a document does not
    /// care which page an image came from, only that none is skipped.
    pub fn all_images(&self) -> Vec<PageImage> {
        (0..self.page_count())
            .flat_map(|i| self.page_images(i))
            .collect()
    }

    /// The `/JBIG2Globals` stream of an image dictionary, if it has one.
    ///
    /// The entry lives in the image dictionary, and some producers put it in
    /// the `/DecodeParms` dictionary instead; both are read, because the
    /// difference decides whether the page's glyphs are found or not.
    fn jbig2_globals(&self, sdict: &[(String, PdfObject)]) -> Option<Vec<u8>> {
        let direct = PdfObject::dict_get(sdict, "JBIG2Globals");
        let in_parms = sdict
            .iter()
            .find(|(k, _)| k == "DecodeParms" || k == "DP")
            .and_then(|(_, v)| v.as_dict())
            .and_then(|d| PdfObject::dict_get(d, "JBIG2Globals"));
        let entry = direct.or(in_parms)?;
        let raw = match self.deref(entry)? {
            PdfObject::Stream { raw, .. } => raw,
            _ => return None,
        };
        self.stream_ciphertext(entry, &raw)
    }

    /// Decode one content stream and append it to the page's buffer.
    fn push_stream_bytes(&self, obj: &PdfObject, out: &mut Vec<u8>) {
        if let Some(decoded) = self.decode_stream(obj) {
            out.extend_from_slice(&decoded);
            out.push(b'\n');
        }
    }

    /// Build decoders for every font in the page's /Resources.
    ///
    /// `/Resources` is an indirect reference in almost every real producer's
    /// output — `tesla-valve.pdf` (pdfTeX) writes `/Resources 152 0 R` — so it
    /// is dereferenced here. Without the deref `as_dict()` on a `Ref` returns
    /// `None` and the page gets an empty font map, which is what made the
    /// repository's own paper unsearchable: every `Tf` resolved to no font.
    fn font_decoders(&self, resources: &PdfObject) -> BTreeMap<String, FontDecoder> {
        let mut map = BTreeMap::new();
        let Some(res) = self.deref(resources) else {
            return map;
        };
        let Some(res_dict) = res.as_dict().map(<[(String, PdfObject)]>::to_vec) else {
            return map;
        };
        let Some(fonts_obj) = PdfObject::dict_get(&res_dict, "Font") else {
            return map;
        };
        let Some(PdfObject::Dict(fonts)) = self.deref(fonts_obj) else {
            return map;
        };
        for (name, font_ref) in fonts {
            if let Some(font_obj) = self.deref(&font_ref) {
                if let Some(fd) = font_obj.as_dict() {
                    map.insert(name.clone(), FontDecoder::build(self, fd));
                }
            }
        }
        map
    }

    /// Full-document text with `Page N:` markers (poppler-compatible
    /// shape, so tools downstream can rely on it), plus the fonts that text
    /// had to leave out. One walk: the report is a by-product of it, not a
    /// second pass over the page tree.
    pub fn extract_text_with_notes(&self) -> Extraction {
        let n = self.page_count();
        let mut report = FontReport::default();
        let mut runs = RunReport::default();
        let mut out = String::new();
        for i in 0..n {
            if let Some(text) = self.page_text_with_runs(i, &mut report, &mut runs) {
                let _ = writeln!(out, "Page {}:", i + 1);
                out.push_str(&text);
                out.push('\n');
            }
            if out.len() > MAX_EXTRACT {
                break;
            }
        }
        if out.len() > MAX_EXTRACT {
            let mut cut = MAX_EXTRACT;
            while !out.is_char_boundary(cut) {
                cut -= 1;
            }
            out.truncate(cut);
        }
        Extraction {
            text: out,
            undecodable: report.undecodable,
            missing_fonts: report.missing,
            pages: n,
            runs,
        }
    }

    /// Document info dictionary (`/Info` in the trailer): Title, Author,
    /// Subject, Keywords, Creator, Producer, dates.
    pub fn metadata(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let Some(info_ref) = PdfObject::dict_get(&self.trailer, "Info") else {
            return out;
        };
        // The `/Info` dictionary's strings are encrypted under the Info
        // object's own key, so its object number is needed before any of
        // them can be read — not the trailer's.
        let info_num = match info_ref {
            PdfObject::Ref(n, _) => Some(*n),
            _ => None,
        };
        let Some(PdfObject::Dict(info)) = self.deref(info_ref) else {
            return out;
        };
        for key in [
            "Title",
            "Author",
            "Subject",
            "Keywords",
            "Creator",
            "Producer",
            "CreationDate",
            "ModDate",
        ] {
            if let Some(PdfObject::String(bytes)) = PdfObject::dict_get(&info, key) {
                let plain = match info_num {
                    Some(n) => self.decrypt_string_of(n, bytes),
                    None => bytes.clone(),
                };
                let mut v = String::new();
                decode_text_string_into(&plain, &mut v);
                out.push((key.into(), v));
            }
        }
        out
    }
}

/// PDF text string: UTF-16BE with BOM, or PDFDocEncoding ≈ Latin-1.
#[cfg(all(test, feature = "pdf"))]
pub fn decode_text_string(bytes: &[u8]) -> String {
    let mut out = String::new();
    decode_text_string_into(bytes, &mut out);
    out
}

/// Zero-alloc variant of [`decode_text_string`]: writes directly into
/// `out` rather than allocating a fresh `String` per info-dict field.
/// The PDF info dict reads 8 fields per page, each typically a few
/// hundred bytes; the previous path allocated 8 short-lived Strings
/// per page even when the page already holds one for the body.
pub fn decode_text_string_into(bytes: &[u8], out: &mut String) {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        // UTF-16BE: walk 2-byte units, decode each as a char, push
        // through `char::encode_utf8`. The old path built a `Vec<u16>`
        // of every unit just to hand it to `from_utf16_lossy`, which
        // iterated the same vec a second time.
        for chunk in rest.as_chunks::<2>().0 {
            let unit = u16::from_be_bytes([chunk[0], chunk[1]]);
            // UTF-16 -> char, push as UTF-8. Lone surrogates become the
            // replacement character (U+FFFD); the from_utf16_lossy path
            // did the same thing.
            if let Some(c) = char::from_u32(unit as u32) {
                out.push(c);
            } else {
                out.push('\u{FFFD}');
            }
        }
    } else {
        out.extend(bytes.iter().copied().map(|b| b as char));
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "pdf"))]
mod tests {
    use super::*;

    // --- helpers -----------------------------------------------------------

    fn adler32(data: &[u8]) -> u32 {
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &x in data {
            a = (a + x as u32) % 65521;
            b = (b + a) % 65521;
        }
        (b << 16) | a
    }

    /// Build a valid zlib stream out of stored (uncompressed) deflate blocks,
    /// so fixtures exercise the decoder without a compression dependency.
    fn zlib_stored(data: &[u8]) -> Vec<u8> {
        let mut out = vec![0x78u8, 0x01];
        let mut chunks: Vec<&[u8]> = Vec::new();
        let mut rest = data;
        while rest.len() > 65535 {
            let (head, tail) = rest.split_at(65535);
            chunks.push(head);
            rest = tail;
        }
        chunks.push(rest);
        let last = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            out.push(if i == last { 1 } else { 0 }); // BFINAL, BTYPE=00
            let len = chunk.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&adler32(data).to_be_bytes());
        out
    }

    fn unhex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s.bytes().filter_map(hex_val).collect();
        digits
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| (c[0] << 4) | c[1])
            .collect()
    }

    // --- zlib / inflate vectors --------------------------------------------

    // zlib (level 9) of: BT /F1 12 Tf 72 720 Td (Hello from rgx pdf) Tj ET
    const Z_FIXED: &str = "78da730a51d07733543034520849533037022203859014050d8fd49c9c7c85b4a2fc5c85a2f40a858294344d85902c05d7100032f70d6f";
    const Z_EMPTY: &str = "78da030000000001";
    // zlib (dynamic Huffman) of 800 weighted-random words, seed 42 → 4649 bytes
    const Z_DYN: &str = "78da8d575b6ec3300cbb4aaf1623c65aac5d032c5f3efd80b8a9299272f79375b62ceb4151f25aeffb7259eedb75b994fafe59b7dfdbfdf973598fed569d4cff7e2d8f475ce96770bdff3e75ba1b40ed7eadbbb9e7b0a10b9f47cfbf5d3d9ceb0b70a28dd5151c4e5c8265b0ae5010c636aa8c4e1e82b7e71e83023645713884b93885d9a2e11448c302840104be976d7369c3e49d66b1cf78b6c71ba081c1002b5646d80b0dc12b34c7f9eb421c51851a5cf0380ced8ca0c298f18512e0186b742887a841e234f8c9320696fcc90486181aec5d62bc45d9aef5402f0b36cf020eb9431eddeb2139963b8e486b92cd514f05ab076eefda10a782bf2ee2a2a3896ecc4beab4065ffc90d48f12d0045ade71167627fb57f239c73d1615d053843f18e219528a1cb588cfd53492b4e364e995303722baa4b402d9360be16806131055df0bb4286c8227327137e4948d32cebbe2651fa10b42248f1c33e810d0d2748b982bc48ea1e62021eed34ecf206f0ef9f4b10d980f0a7b14b629699b694f963a66425516d0e38c7e2d9734a496be656852f0b729ad53616a03e7ea4a2b32665aa2c5a948da9db248b1330e4d3f669eca90fceefa8660a693215794b6a9c46cdd9cf5364b106d46bf9dff8b4ec7342b4fd099612fa2cdad9dff696f04838492b264077f71e3006b080da348491eebc2b34434de00c2506f897df573bf1709d3269ac556b5dc10b3eb7634b33278648e890d19e83e5124d2d1549d0c12781221e0fb7c7283925ef1b3965c8fd3942fa4d963604ca6989eac04ffd33212a2d5d764dd3d366cf79bbe3c3f70fcd08016cedeaf58892dce83f23272b30f8fa0dac7f95ea877f7664eabbcd004d5b7e4fd9e91760e144b80c84d59e691ffc8dd36996960141488532135213f927a2dff019d7d8c3d";

    #[test]
    fn zlib_fixed_huffman() {
        let out = zlib_decode(&unhex(Z_FIXED)).expect("fixed-huffman zlib");
        assert_eq!(out, b"BT /F1 12 Tf 72 720 Td (Hello from rgx pdf) Tj ET");
    }

    #[test]
    fn zlib_empty() {
        let out = zlib_decode(&unhex(Z_EMPTY)).expect("empty zlib");
        assert!(out.is_empty());
    }

    #[test]
    fn zlib_dynamic_huffman() {
        // 653-byte zlib stream with dynamic Huffman tables → 4649 bytes.
        let z = unhex(Z_DYN);
        let out = zlib_decode(&z).expect("dynamic-huffman zlib");
        assert_eq!(out.len(), 4649);
        assert!(out.starts_with(b"delta alpha beta alpha epsilon delta zeta alpha beta alpha a"));
        let text = String::from_utf8_lossy(&out);
        for w in ["alpha", "beta", "gamma", "delta", "kappa"] {
            assert!(text.contains(w), "missing {w}");
        }
    }

    #[test]
    fn zlib_stored_roundtrip() {
        let data: Vec<u8> = (0..200_000u32)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        let z = zlib_stored(&data);
        assert_eq!(zlib_decode(&z).as_deref(), Some(&data[..]));
    }

    #[test]
    fn inflate_rejects_garbage() {
        assert!(zlib_decode(b"not zlib at all").is_none());
        assert!(inflate(&[0xFF; 16]).is_none());
    }

    // --- classic filters -----------------------------------------------------

    #[test]
    fn ascii85_known_and_z() {
        assert_eq!(ascii85_decode(b"9jqo^~>").as_deref(), Some(&b"Man "[..]));
        assert_eq!(ascii85_decode(b"z~>").as_deref(), Some(&[0u8; 4][..]));
        assert_eq!(ascii85_decode(b"<~!!!!!~>").as_deref(), Some(&[0u8; 4][..]));
    }

    #[test]
    fn asciihex_basic() {
        assert_eq!(
            asciihex_decode(b"48656C6C6F>").as_deref(),
            Some(&b"Hello"[..])
        );
        assert_eq!(
            asciihex_decode(b"48656C6C6F").as_deref(),
            Some(&b"Hello"[..])
        ); // odd nibble padded
        assert_eq!(
            asciihex_decode(b"48 65 6C 6C 6F>").as_deref(),
            Some(&b"Hello"[..])
        );
    }

    #[test]
    fn runlength_basic() {
        // 2 bytes literal "AB", then run of 5 x 0x41, then EOD
        let enc = [0x01, b'A', b'B', (257 - 5) as u8, 0x41, 0x80];
        assert_eq!(runlength_decode(&enc).as_deref(), Some(&b"ABAAAAA"[..]));
    }

    fn push_bits(out: &mut Vec<u8>, buf: &mut u64, cnt: &mut u32, code: u16, width: u32) {
        *buf = (*buf << width) | code as u64;
        *cnt += width;
        while *cnt >= 8 {
            *cnt -= 8;
            out.push((*buf >> *cnt) as u8);
            *buf &= (1u64 << *cnt) - 1;
        }
    }

    /// LZW encoder mirroring `lzw_decode`'s width schedule (MSB-first,
    /// EarlyChange): a data code #k is emitted with the width the decoder
    /// will use when reading it, i.e. the width after add #(k-2).
    fn lzw_encode(data: &[u8], early_change: u32) -> Vec<u8> {
        let mut dict: BTreeMap<Vec<u8>, u16> = BTreeMap::new();
        for b in 0..256u16 {
            dict.insert(vec![b as u8], b);
        }
        let mut next: u16 = 258;
        let mut width: u32 = 9;
        let mut emitted: u32 = 0;
        let mut out: Vec<u8> = Vec::new();
        let mut buf: u64 = 0;
        let mut cnt: u32 = 0;
        push_bits(&mut out, &mut buf, &mut cnt, 256, width); // CLEAR
        let bump = |width: &mut u32, emitted: u32| {
            if emitted >= 1 {
                while 258 + (emitted - 1) + early_change >= (1u32 << *width) && *width < 12 {
                    *width += 1;
                }
            }
        };
        let mut w: Vec<u8> = Vec::new();
        for &b in data {
            let mut cand = w.clone();
            cand.push(b);
            if dict.contains_key(&cand) {
                w = cand;
                continue;
            }
            bump(&mut width, emitted);
            let code = dict[&w];
            push_bits(&mut out, &mut buf, &mut cnt, code, width);
            emitted += 1;
            if next < 4096 {
                dict.insert(cand, next);
                next += 1;
            } else {
                push_bits(&mut out, &mut buf, &mut cnt, 256, width); // CLEAR
                dict.clear();
                for b2 in 0..256u16 {
                    dict.insert(vec![b2 as u8], b2);
                }
                next = 258;
                width = 9;
                emitted = 0;
            }
            w = vec![b];
        }
        if !w.is_empty() {
            bump(&mut width, emitted);
            let code = dict[&w];
            push_bits(&mut out, &mut buf, &mut cnt, code, width);
            emitted += 1;
        }
        bump(&mut width, emitted); // EOD width
        push_bits(&mut out, &mut buf, &mut cnt, 257, width);
        if cnt > 0 {
            out.push((buf << (8 - cnt)) as u8);
        }
        out
    }

    #[test]
    fn lzw_roundtrip_short() {
        let data = b"TOBEORNOTTOBEORTOBEORNOT";
        let enc = lzw_encode(data, 1);
        assert_eq!(lzw_decode(&enc, 1).as_deref(), Some(&data[..]));
    }

    #[test]
    fn lzw_roundtrip_crosses_code_widths() {
        // ~2000 incompressible-ish bytes: the dictionary grows past 511 and
        // 1023 entries, exercising the 9→10→11 bit width transitions.
        let mut state: u32 = 0x12345678;
        let mut data: Vec<u8> = Vec::with_capacity(2000);
        for _ in 0..2000 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            data.push((state >> 24) as u8);
        }
        let enc = lzw_encode(&data, 1);
        assert_eq!(lzw_decode(&enc, 1).as_deref(), Some(&data[..]));
        let enc0 = lzw_encode(&data, 0);
        assert_eq!(lzw_decode(&enc0, 0).as_deref(), Some(&data[..])); // EarlyChange 0
    }

    #[test]
    fn png_predictor_sub() {
        // one row, filter 1 (Sub), bpp 1: raw = 10, 1, 1 → 10, 11, 12
        let data = [1u8, 10, 1, 1];
        assert_eq!(
            png_predictor(&data, 3, 1).as_deref(),
            Some(&[10u8, 11, 12][..])
        );
        // two rows, filter 2 (Up)
        let data = [2u8, 10, 20, 2, 1, 2];
        assert_eq!(
            png_predictor(&data, 2, 1).as_deref(),
            Some(&[10u8, 20, 11, 22][..])
        );
    }

    // --- PDF fixture builder ---------------------------------------------------

    #[derive(Default)]
    struct PdfBuilder {
        buf: Vec<u8>,
        offsets: Vec<(u32, usize)>,
    }

    impl PdfBuilder {
        fn new() -> Self {
            Self {
                buf: b"%PDF-1.7\n".to_vec(),
                offsets: Vec::new(),
            }
        }
        fn obj(&mut self, num: u32, body: &str) {
            self.offsets.push((num, self.buf.len()));
            self.buf
                .extend_from_slice(format!("{num} 0 obj\n").as_bytes());
            self.buf.extend_from_slice(body.as_bytes());
            self.buf.extend_from_slice(b"\nendobj\n");
        }
        fn stream(&mut self, num: u32, dict_extra: &str, data: &[u8]) {
            self.offsets.push((num, self.buf.len()));
            self.buf
                .extend_from_slice(format!("{num} 0 obj\n").as_bytes());
            self.buf.extend_from_slice(
                format!("<< {dict_extra} /Length {} >>\nstream\n", data.len()).as_bytes(),
            );
            self.buf.extend_from_slice(data);
            self.buf.extend_from_slice(b"\nendstream\nendobj\n");
        }
        fn offset_of(&self, num: u32) -> usize {
            self.offsets
                .iter()
                .find(|(n, _)| *n == num)
                .map(|(_, o)| *o)
                .unwrap()
        }
        /// Classic xref table + trailer + startxref.
        fn finish_classic(self, size: u32, trailer_extra: &str) -> Vec<u8> {
            let mut out = self.buf;
            let xref_off = out.len();
            out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
            out.extend_from_slice(b"0000000000 65535 f \n");
            for (_num, off) in &self.offsets {
                out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
            }
            out.extend_from_slice(
                format!(
                    "trailer\n<< /Size {size} /Root 1 0 R {trailer_extra} >>\nstartxref\n{xref_off}\n%%EOF\n"
                )
                .as_bytes(),
            );
            out
        }
        /// Xref *stream* (object `xstm_num`, Flate + PNG-Up predictor) +
        /// startxref pointing at it. `rows` are the raw 7-byte entries for
        /// objects 0..size-1 (kind, f2 BE u32, f3 BE u16).
        fn finish_xref_stream(self, xstm_num: u32, size: u32, rows: &[[u8; 7]]) -> Vec<u8> {
            assert_eq!(rows.len(), size as usize);
            let mut filtered: Vec<u8> = Vec::new();
            let mut prev = [0u8; 7];
            for row in rows {
                filtered.push(2); // Up filter
                for i in 0..7 {
                    filtered.push(row[i].wrapping_sub(prev[i]));
                }
                prev = *row;
            }
            let z = zlib_stored(&filtered);
            let mut out = self.buf;
            let xstm_off = out.len();
            let dict_extra = format!(
                "/Type /XRef /Size {size} /W [1 4 2] /Root 1 0 R \
                 /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >>"
            );
            out.extend_from_slice(format!("{xstm_num} 0 obj\n").as_bytes());
            out.extend_from_slice(
                format!("<< {dict_extra} /Length {} >>\nstream\n", z.len()).as_bytes(),
            );
            out.extend_from_slice(&z);
            out.extend_from_slice(b"\nendstream\nendobj\n");
            out.extend_from_slice(format!("startxref\n{xstm_off}\n%%EOF\n").as_bytes());
            out
        }
    }

    fn row(kind: u8, f2: u64, f3: u64) -> [u8; 7] {
        let mut r = [0u8; 7];
        r[0] = kind;
        r[1..5].copy_from_slice(&(f2 as u32).to_be_bytes());
        r[5..7].copy_from_slice(&(f3 as u16).to_be_bytes());
        r
    }

    const PAGE_CONTENT: &str = "BT /F1 12 Tf 72 720 Td (Hello from rgx pdf) Tj ET";

    fn classic_pdf() -> Vec<u8> {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        );
        b.obj(
            4,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        b.stream(5, "", PAGE_CONTENT.as_bytes());
        b.obj(6, "<< /Title (rgx Test) /Author (upstream) >>");
        b.finish_classic(7, "/Info 6 0 R")
    }

    // --- document-level tests -------------------------------------------------

    #[test]
    fn classic_xref_full_document() {
        let pdf = classic_pdf();
        let doc = PdfReader::parse(&pdf).expect("parse classic pdf");
        assert_eq!(doc.page_count(), 1);
        let text = doc
            .page_text(0, &mut FontReport::default())
            .expect("page text");
        assert!(text.contains("Hello from rgx pdf"), "text: {text:?}");
        let full = doc.extract_text_with_notes().text;
        assert!(full.contains("Page 1:"));
        assert!(full.contains("Hello from rgx pdf"));
        let meta = doc.metadata();
        assert!(meta.iter().any(|(k, v)| k == "Title" && v == "rgx Test"));
        assert!(meta.iter().any(|(k, v)| k == "Author" && v == "upstream"));
    }

    #[test]
    fn xref_stream_document() {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        );
        b.obj(
            4,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        b.stream(5, "", PAGE_CONTENT.as_bytes());
        let rows = vec![
            row(0, 0, 65535),
            row(1, b.offset_of(1) as u64, 0),
            row(1, b.offset_of(2) as u64, 0),
            row(1, b.offset_of(3) as u64, 0),
            row(1, b.offset_of(4) as u64, 0),
            row(1, b.offset_of(5) as u64, 0),
            row(1, 0, 0), // placeholder for the xref stream object itself
        ];
        let pdf = b.finish_xref_stream(6, 7, &rows);
        let doc = PdfReader::parse(&pdf).expect("parse xref-stream pdf");
        assert_eq!(doc.page_count(), 1);
        let text = doc
            .page_text(0, &mut FontReport::default())
            .expect("page text");
        assert!(text.contains("Hello from rgx pdf"), "text: {text:?}");
    }

    #[test]
    fn objstm_document() {
        // Objects 1-4 live compressed inside ObjStm 6; 5 is a plain stream.
        let bodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        ];
        let mut header = String::new();
        let mut offs: Vec<usize> = Vec::new();
        let mut acc = 0usize;
        for (i, body) in bodies.iter().enumerate() {
            let _ = write!(header, "{} {} ", i + 1, acc);
            offs.push(acc);
            acc += body.len();
        }
        let mut stm_content = header.clone().into_bytes();
        for body in &bodies {
            stm_content.extend_from_slice(body.as_bytes());
        }
        let first = header.len();
        let z = zlib_stored(&stm_content);

        let mut b = PdfBuilder::new();
        b.stream(5, "", b"BT /F1 12 Tf 72 720 Td (ObjStm page) Tj ET");
        // ObjStm 6
        b.offsets.push((6, b.buf.len()));
        b.buf.extend_from_slice(b"6 0 obj\n");
        b.buf.extend_from_slice(
            format!(
                "<< /Type /ObjStm /N 4 /First {first} /Filter /FlateDecode /Length {} >>\nstream\n",
                z.len()
            )
            .as_bytes(),
        );
        b.buf.extend_from_slice(&z);
        b.buf.extend_from_slice(b"\nendstream\nendobj\n");

        let rows = vec![
            row(0, 0, 65535),
            row(2, 6, 0),
            row(2, 6, 1),
            row(2, 6, 2),
            row(2, 6, 3),
            row(1, b.offset_of(5) as u64, 0),
            row(1, b.offset_of(6) as u64, 0),
            row(1, 0, 0), // xref stream object itself
        ];
        let pdf = b.finish_xref_stream(7, 8, &rows);
        let doc = PdfReader::parse(&pdf).expect("parse objstm pdf");
        assert_eq!(doc.page_count(), 1);
        let text = doc
            .page_text(0, &mut FontReport::default())
            .expect("page text");
        assert!(text.contains("ObjStm page"), "text: {text:?}");
    }

    #[test]
    fn tounicode_cmap_document() {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        );
        b.obj(
            4,
            "<< /Type /Font /Subtype /Type0 /BaseFont /Identity-H /Encoding /Identity-H /ToUnicode 7 0 R >>",
        );
        b.stream(5, "", b"BT /F1 12 Tf <004100E9010001010102> Tj ET");
        b.obj(6, "<< /Title (CMap Test) >>");
        let cmap = b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
                    /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def\n\
                    1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n\
                    2 beginbfchar\n<0041> <0048>\n<00E9> <0065>\nendbfchar\n\
                    1 beginbfrange\n<0100> <0102> <006700680069>\nendbfrange\n\
                    endcmap\nend\nend\n";
        b.stream(7, "", &cmap[..]);
        let pdf = b.finish_classic(8, "/Info 6 0 R");
        let doc = PdfReader::parse(&pdf).expect("parse cmap pdf");
        let text = doc
            .page_text(0, &mut FontReport::default())
            .expect("page text");
        // 0041→'H', 00E9→'e', bfrange 0100..0102 → "ghi","ghj","ghk"
        assert!(text.contains("Heghighjghk"), "text: {text:?}");
    }

    #[test]
    fn differences_document() {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        );
        b.obj(
            4,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding /Differences [ 65 /A /endash /quotedblleft ] >> >>",
        );
        b.stream(5, "", b"BT /F1 12 Tf (ABC) Tj ET");
        let pdf = b.finish_classic(6, "");
        let doc = PdfReader::parse(&pdf).expect("parse differences pdf");
        let text = doc
            .page_text(0, &mut FontReport::default())
            .expect("page text");
        assert!(text.contains("A\u{2013}\u{201C}"), "text: {text:?}");
    }

    #[test]
    fn encrypted_document_rejected() {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [] /Count 0 >>");
        let pdf = b.finish_classic(3, "/Encrypt 9 0 R");
        assert!(matches!(PdfDocument::parse(&pdf), Err(PdfError::Encrypted)));
    }

    #[test]
    fn bad_magic_rejected() {
        assert!(matches!(
            PdfDocument::parse(b"%PNG-1.7\nnot a pdf"),
            Err(PdfError::BadMagic)
        ));
    }

    #[test]
    fn truncated_documents_never_panic() {
        let pdf = classic_pdf();
        let mut cuts: Vec<usize> = (0..=pdf.len()).step_by(97).collect();
        cuts.push(pdf.len() - 1);
        for cut in cuts {
            let data = &pdf[..cut];
            if let Ok(doc) = PdfDocument::parse(data) {
                let _ = doc.page_count();
                let _ = doc.extract_text_with_notes();
                let _ = doc.metadata();
            }
        }
    }

    #[test]
    fn a_long_run_of_unparseable_bytes_costs_one_stack_frame_not_one_per_byte() {
        // `Lexer::next_tok` used to tail-call itself for every byte it could
        // not start a token on, so a run of 0xFF cost a stack frame each.
        // `fuzzkit` hit it with a 13 KB PDF mutated into 6.5 KB of 0xFF and
        // the reader died of stack overflow on its way to returning `Bail`.
        // The lexer is a loop now, and the budget this asserts is the whole
        // call: 512 KB of junk that used to be 512 KB of stack.
        let mut pdf = classic_pdf();
        let junk = vec![0xFFu8; 512 * 1024];
        pdf.extend_from_slice(&junk);
        pdf.extend_from_slice(classic_pdf().as_slice());
        let doc = PdfDocument::parse(&pdf);
        if let Ok(doc) = doc {
            let _ = doc.page_count();
            let _ = doc.extract_text_with_notes();
        }
    }

    #[test]
    fn decode_text_string_utf16() {
        assert_eq!(decode_text_string(b"Hello"), "Hello");
        assert_eq!(
            decode_text_string(&[0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69]),
            "Hi"
        );
    }

    // --- encoding resolution ------------------------------------------------
    //
    // These hold down the two decisions that decide whether a font's bytes
    // become the right characters or the wrong ones: which encoding a
    // simple font's codes are in, and what happens when there is no way to
    // know. A regression in either is silent — the reader still returns a
    // String — so the assertions are on exact code points, not on "some
    // text came out".

    /// One page, one Type 1 font whose dict is `font`, one content stream.
    /// `/Resources` is an indirect reference, which is how every real
    /// producer writes it.
    fn one_page(font: &str, content: &[u8]) -> Vec<u8> {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources 4 0 R /Contents 5 0 R >>",
        );
        b.obj(4, "<< /Font << /F1 6 0 R >> >>");
        b.stream(5, "", content);
        b.obj(6, font);
        b.finish_classic(7, "")
    }

    /// One page's text, which is empty when nothing in it decoded, plus the
    /// report either way — an empty page is the interesting case, not a
    /// failure of the helper.
    fn text_of(pdf: &[u8]) -> (String, FontReport) {
        let doc = PdfDocument::parse(pdf).expect("parse");
        let mut report = FontReport::default();
        let text = doc.page_text(0, &mut report).unwrap_or_default();
        (text, report)
    }

    #[test]
    fn an_indirect_resources_reference_still_yields_the_page_fonts() {
        // The whole of `tesla-valve.pdf` was invisible to this crate
        // because `font_decoders` called `as_dict()` on the *reference*
        // rather than on what it points at, got `None`, and handed every
        // page an empty font map. A document whose page text is empty fails
        // the same way as one whose font really is missing, so the
        // assertion has to be on the text.
        let pdf = one_page(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            b"BT /F1 12 Tf 20 100 Td (Valve) Tj ET",
        );
        let (text, report) = text_of(&pdf);
        assert!(text.contains("Valve"), "{text:?}");
        assert_eq!(report.missing, 0, "{report:?}");
    }

    #[test]
    fn a_word_space_split_across_a_typeface_change_is_still_a_space() {
        // The kerning number is the gap between the glyph shown last and the
        // one shown next, and pdfTeX closes a `TJ` array whenever the
        // typeface changes — so the word space lands at the head of the
        // *next* array. Requiring a string to have been seen in the same
        // array lost it, and `tesla-valve.pdf` came out as "theTesla",
        // which is a phrase nobody types.
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>",
        );
        let helv =
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
        b.obj(4, helv);
        b.obj(5, helv);
        b.stream(
            6,
            "",
            b"BT /F1 12 Tf 20 100 Td [(formalise)-249(the)]TJ /F2 12 Tf [-249(T)92(esla)-249(Val)10(ve)]TJ ET",
        );
        let pdf = b.finish_classic(7, "");
        let (text, _) = text_of(&pdf);
        assert!(text.contains("formalise the Tesla Valve"), "{text:?}");
    }

    #[test]
    fn a_tj_array_with_bracket_operands_still_shows_its_strings() {
        // `TJ` takes an array, and the tokenizer emits `[` and `]` as
        // tokens. Treating them as operators emptied the operand stack
        // before `TJ` ever ran, so every array-form text-showing operator
        // was a no-op — and pdfTeX, which produced this crate's own
        // flagship document, emits nothing but `TJ`.
        let pdf = one_page(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            b"BT /F1 12 Tf 20 100 Td [(the)-250(valve)]TJ ET",
        );
        let (text, _) = text_of(&pdf);
        assert!(text.contains("the"), "{text:?}");
        assert!(text.contains("valve"), "{text:?}");
    }

    #[test]
    fn standard_encoding_reads_the_two_quotes_latin1_would_get_wrong() {
        // The whole reason StandardEncoding is a table and not "ASCII": at
        // 0x27 it is U+2019 and at 0x60 it is U+2018. Latin-1 would answer
        // U+0027 and U+0060, which are the two characters a search for a
        // typographic quote misses and a search for a straight quote finds
        // in text that does not contain one.
        let s = BaseEncoding::Standard;
        assert_eq!(s.decode(0x27), Some('\u{2019}'));
        assert_eq!(s.decode(0x60), Some('\u{2018}'));
        assert_eq!(s.decode(0x41), Some('A'));
        // endash and emdash sit at 0xB1 and 0xD0, and are not Latin-1.
        assert_eq!(s.decode(0xB1), Some('\u{2013}'));
        assert_eq!(s.decode(0xD0), Some('\u{2014}'));
        // 0x8A is a hole in StandardEncoding; the point is that it is
        // dropped rather than read as U+008A.
        assert_eq!(s.decode(0x8A), None);
        assert_eq!(s.decode(0x7E), Some('~'));
        assert_eq!(s.decode(0x00), None);
    }

    #[test]
    fn a_type1_font_with_no_encoding_reads_as_standard_not_latin1() {
        // PDF 32000-1 9.2.4: with no /Encoding the base encoding is the
        // font's own, which for a non-symbolic Type 1 is StandardEncoding.
        // The default is what a LaTeX-emitted base-14 reference looks like.
        let pdf = one_page(
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"BT /F1 12 Tf 20 100 Td (Valve\\'s) Tj ET",
        );
        let (text, report) = text_of(&pdf);
        assert!(text.contains('\u{2019}'), "{text:?}");
        assert!(!text.contains('\''), "{text:?}");
        assert!(report.undecodable.is_empty(), "{report:?}");
    }

    #[test]
    fn a_nonsymbolic_truetype_font_with_no_encoding_reads_as_winansi() {
        let pdf = one_page(
            "<< /Type /Font /Subtype /TrueType /BaseFont /SomeTTF >>",
            b"BT /F1 12 Tf 20 100 Td (Valve\\'s) Tj ET",
        );
        let (text, _) = text_of(&pdf);
        assert!(text.contains("Valve's"), "{text:?}");
        assert!(!text.contains('\u{2019}'), "{text:?}");
    }

    #[test]
    fn a_symbolic_font_with_no_encoding_is_reported_not_decoded() {
        // Its encoding is in the font program. Reading the codes as Latin-1
        // would answer every query with a confident wrong line.
        let pdf = one_page(
            concat!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /Sym",
                " /FontDescriptor << /Flags 4 /FontName /Sym >> >>"
            ),
            b"BT /F1 12 Tf 20 100 Td (Valve) Tj ET",
        );
        let (text, report) = text_of(&pdf);
        assert!(text.trim().is_empty(), "nothing should decode: {text:?}");
        assert_eq!(
            report.undecodable,
            vec![("symbolic font whose encoding lives in the font program", 1)]
        );
    }

    #[test]
    fn a_differences_array_of_opaque_glyph_names_is_reported_not_read_as_latin1() {
        // `/a97` says which glyph, not which character. A Latin-1 fallback
        // answers code 97 with the letter `a`, which is a wrong line, not
        // a missing one.
        let pdf = one_page(
            concat!(
                "<< /Type /Font /Subtype /Type3 /CharProcs << >>",
                " /Encoding << /Differences [ 97 /a97 98 /a98 ] >> >>"
            ),
            b"BT /F1 12 Tf 20 100 Td <61 62 63> Tj ET",
        );
        let (text, report) = text_of(&pdf);
        assert!(!text.contains('a'), "{text:?}");
        assert!(!text.contains('b'), "{text:?}");
        assert!(!text.contains('c'), "{text:?}");
        assert_eq!(
            report.undecodable,
            vec![(
                "/Encoding /Differences names only glyphs with no Unicode",
                1
            )]
        );
    }

    #[test]
    fn a_composite_font_with_no_tounicode_reports_rather_than_reading_cids_as_unicode() {
        // The old `char::from_u32(code)` arm turned CID 3 into U+0003: a
        // NUL in the corpus, which is what made the extracted text look
        // binary to the searcher.
        let pdf = one_page(
            "<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H >>",
            b"BT /F1 12 Tf 20 100 Td <00030004> Tj ET",
        );
        let (text, report) = text_of(&pdf);
        assert!(!text.contains('\u{3}'), "{text:?}");
        assert!(!text.contains('\u{4}'), "{text:?}");
        assert_eq!(
            report.undecodable,
            vec![("composite font with no /ToUnicode CMap", 1)]
        );
    }

    #[test]
    fn a_font_the_content_stream_names_but_resources_does_not_define_is_counted() {
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources 4 0 R /Contents 5 0 R >>",
        );
        b.obj(4, "<< /Font << /F1 6 0 R >> >>");
        b.stream(5, "", b"BT /F9 12 Tf 20 100 Td (Valve) Tj ET");
        b.obj(
            6,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        let pdf = b.finish_classic(7, "");
        let (_text, report) = text_of(&pdf);
        assert_eq!(report.missing, 1, "{report:?}");
    }

    #[test]
    fn a_tounicode_cmap_keeps_priority_over_every_other_encoding() {
        // Same font, three mappings, one code: the CMap wins, and the
        // report stays empty because nothing was lost.
        let mut b = PdfBuilder::new();
        b.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        b.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        );
        b.obj(
            4,
            concat!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding",
                " << /Type /Encoding /BaseEncoding /WinAnsiEncoding",
                " /Differences [ 65 /bullet ] >>",
                " /ToUnicode 6 0 R >>"
            ),
        );
        b.stream(5, "", b"BT /F1 12 Tf 20 100 Td (A) Tj ET");
        let cmap = b"/CIDInit /ProcSet findresource begin\nbegincmap\n\
                    1 begincodespacerange\n<00> <FF>\nendcodespacerange\n\
                    1 beginbfchar\n<41> <005A>\nendbfchar\nendcmap\nend\n";
        b.stream(6, "", cmap);
        let pdf = b.finish_classic(7, "");
        let (text, report) = text_of(&pdf);
        assert!(text.contains('Z'), "{text:?}");
        assert!(!text.contains('A'), "{text:?}");
        assert!(!text.contains('\u{2022}'), "{text:?}");
        assert!(report.undecodable.is_empty(), "{report:?}");
    }
}

/// An image drawn on a page, as far as this crate can honestly take it.
#[derive(Debug, Clone)]
pub struct PageImage {
    pub width: u32,
    pub height: u32,
    pub bits: u8,
    /// The stream's `/Filter`, or `""` when it has none. Named rather than
    /// dropped, because "this page carries an image I cannot decode" and
    /// "this page carries no image" are different answers.
    pub filter: String,
    /// The stored bytes, when `/DCTDecode` means they already are a JPEG.
    pub jpeg: Option<Vec<u8>>,
    /// A complete PNG, when this crate could turn the stored bytes into a
    /// picture: a CCITT fax scan decoded to pixels and wrapped. Present
    /// *instead of* `jpeg`, never alongside it — a consumer that has to pick
    /// between two answers for one image is a consumer that will pick wrong.
    pub png: Option<Vec<u8>>,
}

/// Decode a `/CCITTFaxDecode` stream and wrap the result as a PNG.
///
/// The PNG is grey and stored-deflate on purpose. Its job is to be handed to
/// a subprocess and thrown away, so the bytes that make it small matter less
/// than the bytes that make it *correct*; see `rgx_core::png`.
///
/// A stream that does not decode yields `None` rather than a partial page:
/// half a scan reads as a bad image, and the report names the codec so the
/// difference between "this page has an image I could not render" and
/// "this page has no image" survives.
fn decode_fax_png(raw: &[u8], parms: &DecodeParms, width: u32, height: u32) -> Option<Vec<u8>> {
    let p = fax::FaxParams {
        k: parms.k,
        columns: parms.columns.max(0) as u32,
        // `/Rows` wins when present; the image dictionary's `/Height` is the
        // fallback, and the two disagree in real files more often than the
        // specification suggests.
        rows: if parms.rows > 0 {
            parms.rows as u32
        } else {
            height
        },
        black_is_1: parms.black_is_1 != 0,
        byte_align: parms.byte_align != 0,
    };
    let width = if width > 0 { width } else { p.columns };
    let pixels = fax::decode_fax(raw, &p)?;
    // The height is the number of rows that were decoded, not the one the
    // dictionary claims: a block the encoder ended with `EOFB` can be
    // shorter than `/Rows`, and the rows it holds are still a page worth
    // reading. `encode_gray8` refuses a mismatch on its own, so a height
    // taken from the claim instead would drop the whole image over a
    // difference of a few rows.
    let height = match width {
        0 => return None,
        w => (pixels.len() / w as usize) as u32,
    };
    if height == 0 {
        return None;
    }
    rgx_core::png::encode_gray8(width, height, &pixels)
}

/// Decode a `/JBIG2Decode` stream and wrap the result as a PNG.
///
/// The PNG is grey and stored-deflate on the same terms as the fax one: it
/// is handed to a subprocess and thrown away, so it has to be correct
/// rather than small.
///
/// A stream that does not decode yields `None` rather than a partial page:
/// half a page reads as a bad image, and the report names the codec so the
/// difference between "this page has an image I could not render" and "this
/// page has no image" survives.
fn decode_jbig2_png(
    globals: Option<&[u8]>,
    raw: &[u8],
    width: u32,
    height: u32,
) -> Option<Vec<u8>> {
    let image = jbig2::decode_with_size(globals, raw, width, height)?;
    rgx_core::png::encode_gray8(image.width, image.height, &image.pixels)
}

/// The `/Filter` of a stream as a name, taking the first of an array.
fn stream_filter_name(dict: &[(String, PdfObject)]) -> String {
    match PdfObject::dict_get(dict, "Filter") {
        Some(PdfObject::Name(n)) => n.clone(),
        Some(PdfObject::Array(items)) => match items.first() {
            Some(PdfObject::Name(n)) => n.clone(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn dict_int(dict: &[(String, PdfObject)], key: &str) -> Option<u64> {
    match PdfObject::dict_get(dict, key)? {
        PdfObject::Int(n) => Some(*n as u64),
        PdfObject::Real(r) => Some(*r as u64),
        _ => None,
    }
}

/// Every page image a PDF carries, flattened.
///
/// The caller OCRing a document does not care which page an image came from,
/// only that none is skipped silently — which is why `PageImage` names the
/// filter for the ones that cannot be read instead of hiding them.
///
/// An empty vector means there is no image to read, which is a different
/// answer from "there is an image and it is unreadable": a PDF that is not
/// a PDF, and a scan stored as CCITT G4, both come back empty here and the
/// caller has to say which it was.
pub fn all_page_images(data: &[u8]) -> Vec<PageImage> {
    match PdfDocument::parse(data) {
        Ok(doc) => doc.all_images(),
        Err(_) => Vec::new(),
    }
}

#[cfg(all(test, feature = "pdf"))]
mod scan_images {
    //! The page images a scanned PDF hands to an OCR engine.
    //!
    //! The case that matters is the one a real scanner produces: the page
    //! *is* a picture, `/DCTDecode` because that filter is JPEG, and the
    //! document's own text extraction returns nothing for it. A filter this
    //! tree cannot undo is the other half — it has to come back named rather
    //! than absent, because "this page has no image" and "this page has an
    //! image I cannot read" send the reader to different places.

    use super::all_page_images;
    use alloc::vec::Vec;

    /// A one-page PDF whose page draws one image with the given filter.
    fn pdf_with_image(filter: &str, payload: &[u8]) -> Vec<u8> {
        let mut objs: Vec<Vec<u8>> = Vec::new();
        let image_stream = format!(
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 \
             /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /{filter} \
             /Length {} >>\nstream\n",
            payload.len()
        )
        .into_bytes();
        let mut image = image_stream;
        image.extend_from_slice(payload);
        image.extend_from_slice(b"\nendstream");

        objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        objs.push(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec());
        objs.push(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        );
        objs.push(image);
        let content = b"q 612 0 0 792 0 0 cm /Im0 Do Q";
        objs.push(
            format!("<< /Length {} >>\nstream\n", content.len())
                .into_bytes()
                .into_iter()
                .chain(content.iter().copied())
                .chain(b"\nendstream".iter().copied())
                .collect(),
        );

        let mut out = b"%PDF-1.4\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    /// A one-page PDF whose page draws one JBIG2 image, with the glyph
    /// dictionary a text region needs when it has one.
    fn pdf_with_jbig2(page: &[u8], globals: Option<&[u8]>) -> Vec<u8> {
        let mut objs: Vec<Vec<u8>> = Vec::new();
        let parms = match globals {
            Some(_) => " /DecodeParms << /JBIG2Globals 6 0 R >>",
            None => "",
        };
        let mut image = format!(
            "<< /Type /XObject /Subtype /Image /Width 1240 /Height 320 \
             /ColorSpace /DeviceGray /BitsPerComponent 1 /Filter /JBIG2Decode{parms} \
             /Length {} >>\nstream\n",
            page.len()
        )
        .into_bytes();
        image.extend_from_slice(page);
        image.extend_from_slice(b"\nendstream");

        objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        objs.push(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec());
        objs.push(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1240 320] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        );
        objs.push(image);
        let content = b"q 1240 0 0 320 0 0 cm /Im0 Do Q";
        objs.push(
            format!("<< /Length {} >>\nstream\n", content.len())
                .into_bytes()
                .into_iter()
                .chain(content.iter().copied())
                .chain(b"\nendstream".iter().copied())
                .collect(),
        );
        if let Some(g) = globals {
            let mut stream = format!("<< /Length {} >>\nstream\n", g.len()).into_bytes();
            stream.extend_from_slice(g);
            stream.extend_from_slice(b"\nendstream");
            objs.push(stream);
        }

        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, body) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in &offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }

    /// A JBIG2 scan is a program against a template, not a picture, so the
    /// page image comes back as a PNG this crate built.
    #[test]
    fn a_jbig2_page_image_comes_back_as_a_png() {
        let page = include_bytes!("../testdata/jbig2/jbig2_text.arith_t0.jb2");
        let pdf = pdf_with_jbig2(page, None);
        let images = all_page_images(&pdf);
        assert_eq!(images.len(), 1, "one page image");
        assert_eq!(images[0].filter, "JBIG2Decode");
        assert!(images[0].jpeg.is_none(), "it is not handed over as bytes");
        let png = images[0].png.as_deref().expect("the scan is decoded");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "a PNG header");
    }

    /// A text region needs the glyph dictionary, and it comes from the
    /// globals the image dictionary points at.
    #[test]
    fn a_jbig2_text_region_with_its_globals_comes_back_as_a_png() {
        let page = include_bytes!("../testdata/jbig2/jbig2_text.symbol.jb2");
        let globals = include_bytes!("../testdata/jbig2/jbig2_text.symbol.globals");
        let pdf = pdf_with_jbig2(page, Some(globals));
        let images = all_page_images(&pdf);
        assert_eq!(images.len(), 1, "one page image");
        let png = images[0].png.as_deref().expect("the scan is decoded");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n", "a PNG header");
    }

    /// A JBIG2 stream that does not decode is not a page, and a page that
    /// comes back blank is a different page.
    #[test]
    fn a_jbig2_page_image_that_does_not_decode_is_named_not_dropped() {
        let pdf = pdf_with_jbig2(b"not a jbig2 stream at all", None);
        let images = all_page_images(&pdf);
        assert_eq!(images.len(), 1, "the image is still reported");
        assert!(images[0].png.is_none(), "but it is not handed over");
        assert_eq!(images[0].filter, "JBIG2Decode");
    }

    /// A JPEG is not undone: `/DCTDecode` means the stored bytes already are
    /// one, so decoding them into samples would destroy the image.
    #[test]
    fn a_dctdecode_page_image_comes_back_as_the_stored_jpeg() {
        let jpeg = [0xffu8, 0xd8, b'R', b'G', b'X', 0xff, 0xd9];
        let pdf = pdf_with_image("DCTDecode", &jpeg);
        let images = all_page_images(&pdf);
        assert_eq!(images.len(), 1, "one page image");
        assert_eq!(
            images[0].jpeg.as_deref(),
            Some(&jpeg[..]),
            "bytes untouched"
        );
        assert_eq!(images[0].filter, "DCTDecode");
        assert_eq!(images[0].width, 8);
        assert_eq!(images[0].height, 8);
    }

    /// The filter this tree cannot undo is named instead of dropped.
    #[test]
    fn a_page_image_in_a_codec_this_tree_cannot_undo_is_named_not_dropped() {
        let pdf = pdf_with_image("CCFDecode", &[0u8; 32]);
        let images = all_page_images(&pdf);
        assert_eq!(images.len(), 1, "the image is still reported");
        assert!(images[0].jpeg.is_none(), "but it is not handed over");
        assert_eq!(images[0].filter, "CCFDecode");
    }

    #[test]
    fn a_document_with_no_images_reports_none() {
        let pdf = b"%PDF-1.4\n<< /Type /Catalog >>\n%%EOF\n";
        assert!(all_page_images(pdf).is_empty());
    }

    #[test]
    fn something_that_is_not_a_pdf_reports_none_rather_than_panicking() {
        assert!(all_page_images(b"").is_empty());
        assert!(all_page_images(&[0xff, 0xd8, 0xff, 0xe0]).is_empty());
        assert!(all_page_images(b"%PDF-1.4\ntruncated").is_empty());
    }
}
