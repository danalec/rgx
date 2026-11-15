// SPDX-License-Identifier: Apache-2.0

//! The adaptive arithmetic codec of CRAM 3.1.
//!
//! The codec is the range coder of the "CRAM codec specification", with the
//! adaptive model of its section 4.1 and the order-0, order-1 and run-length
//! streams of its sections 4.2 and 4.3. The frame is a flag byte, the
//! uncompressed length and the data, and the flag byte says what the data
//! is: the bytes themselves, an entropy-coded stream, a run-length coded
//! stream, an interleaving of sub-streams, or a bzip2 stream.
//!
//! The pseudocode this follows is the "CRAM codec specification" of the
//! hts-specs repository (section 4), which is the document the CRAM 3.1
//! specification points at. The frames the tests carry were written by the
//! reference implementation of that codec, the htscodecs library, and not by
//! this reader.

use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "cram")]
use rgx_core::compress::bzip2::Bzip2Decoder;

/// The largest a decoded block may be.
///
/// The size comes from the frame itself, so a corrupt one could ask for a
/// gigabyte before it is refused. The ceiling is the same one the other
/// decompressors of this crate use.
#[cfg(feature = "cram")]
const MAX_OUTPUT: usize = 32 << 20;

/// The flag byte's bits, as the table of the specification gives them.
#[cfg(feature = "cram")]
mod flag {
    /// Order-1 entropy coding. Unset means order-0.
    pub const ORDER: u8 = 0x01;
    /// Reserved for a possible order-2 or order-3 codec.
    pub const RESERVED: u8 = 0x02;
    /// The data is compressed by an external codec, which is bzip2.
    pub const EXT: u8 = 0x04;
    /// The data is an interleaving of sub-streams.
    pub const STRIPE: u8 = 0x08;
    /// The frame does not carry the length of the uncompressed data.
    pub const NOSIZE: u8 = 0x10;
    /// The data is stored as it is.
    pub const CAT: u8 = 0x20;
    /// The literals are run-length coded.
    pub const RLE: u8 = 0x40;
    /// The data is bit-packed.
    pub const PACK: u8 = 0x80;
}

/// The range coder renormalises when its range falls below this.
#[cfg(feature = "cram")]
const TOP: u32 = 1 << 24;

/// The largest a model's total frequency may grow to.
///
/// The specification renormalises the model when the total passes
/// `2^16 - 17`, so that the total never passes the largest 16-bit number.
#[cfg(feature = "cram")]
const MAX_FREQ: u32 = (1 << 16) - 17;

/// The step a model's frequency grows by when a symbol is decoded.
#[cfg(feature = "cram")]
const STEP: u16 = 16;

/// The run length that says another run length follows.
///
/// The run lengths are the four symbols of the run model, and the length
/// three is the one that means "read another length and add it to this
/// one".
#[cfg(feature = "cram")]
const RUN_CONTINUE: u8 = 3;

/// The number of run models: one per literal symbol, one for the first
/// continuation and one for the rest.
#[cfg(feature = "cram")]
const RUN_MODELS: usize = 258;

/// The context of the first continuation of a run: 256.
#[cfg(feature = "cram")]
const RUN_CTX_FIRST: usize = 256;

/// The context of the continuations after the first: 257.
#[cfg(feature = "cram")]
const RUN_CTX_NEXT: usize = 257;

/// A byte reader over the frame's bytes.
///
/// Shared with the fqzcomp codec of CRAM 3.1, which reads its parameters
/// with the same reader.
#[cfg(feature = "cram")]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

#[cfg(feature = "cram")]
impl<'a> Reader<'a> {
    /// A reader over the bytes of the frame.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    /// The next byte, or `None` when the frame ends before it.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    /// The next `n` bytes, or `None` when the frame holds fewer.
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.data.get(self.at..end)?;
        self.at = end;
        Some(s)
    }

    /// The bytes of the frame that are left.
    fn rest(&self) -> &'a [u8] {
        &self.data[self.at..]
    }

    /// The 7-bit unsigned integer of the specification: seven bits per byte,
    /// most significant group first, with the top bit set on every byte but
    /// the last.
    ///
    /// `None` when the integer needs more than five bytes, which no value
    /// this reader can hold has.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1, whose frame opens with
    /// such an integer.
    pub(crate) fn uint7(&mut self) -> Option<u32> {
        let mut value = 0u64;
        for i in 0..5 {
            let b = self.byte()?;
            value = (value << 7) | u64::from(b & 0x7f);
            if b & 0x80 == 0 {
                return u32::try_from(value).ok();
            }
            if i == 4 {
                // A sixth byte: the value does not fit.
                return None;
            }
        }
        None
    }
}

/// The range coder of the specification: a range and a code, both 32-bit
/// unsigned and both wrapping.
///
/// Shared with the fqzcomp codec of CRAM 3.1, whose values are coded with
/// the same coder.
#[cfg(feature = "cram")]
pub(crate) struct RangeCoder<'a, 'b> {
    reader: &'b mut Reader<'a>,
    range: u32,
    code: u32,
}

#[cfg(feature = "cram")]
impl<'a, 'b> RangeCoder<'a, 'b> {
    /// The coder's first state.
    ///
    /// The range is the largest 32-bit unsigned value and the code is the
    /// next five bytes of the stream, of which the first is shifted out of
    /// the 32-bit word: the code is the last four of them, big-endian.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn new(reader: &'b mut Reader<'a>) -> Option<Self> {
        let mut code = 0u32;
        for _ in 0..5 {
            code = (code << 8) | u32::from(reader.byte()?);
        }
        Some(Self {
            reader,
            range: u32::MAX,
            code,
        })
    }

    /// The cumulative frequency the code falls into.
    ///
    /// The range is divided by the total frequency first, and the divided
    /// range is what the decode step that follows works on.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn get_freq(&mut self, total: u32) -> Option<u32> {
        if total == 0 || self.range < total {
            // The code cannot be placed in a range this small.
            return None;
        }
        self.range /= total;
        Some(self.code / self.range)
    }

    /// The decode step: the code loses the part of the range below the
    /// symbol, and the range shrinks to the symbol's own share of it.
    ///
    /// The range is renormalised afterwards, reading a byte for every byte
    /// it is short of.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn decode(&mut self, cum: u32, freq: u32) -> Option<()> {
        self.code = self.code.wrapping_sub(cum.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(freq);
        while self.range < TOP {
            self.code = (self.code << 8) | u32::from(self.reader.byte()?);
            self.range <<= 8;
        }
        Some(())
    }
}

/// The adaptive model of the specification: a list of symbols with their
/// frequencies, held roughly sorted by frequency.
///
/// Shared with the fqzcomp codec of CRAM 3.1, whose models are the same.
#[cfg(feature = "cram")]
#[derive(Clone)]
pub(crate) struct Model {
    /// The symbols, in the order the model holds them.
    sym: Vec<u8>,
    /// The frequency of each symbol of `sym`.
    freq: Vec<u16>,
    /// The sum of the frequencies.
    total: u32,
}

#[cfg(feature = "cram")]
impl Model {
    /// A model of `num_sym` symbols, every one of them with the frequency
    /// of one: the specification never lets a frequency fall to zero.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn new(num_sym: usize) -> Self {
        let sym = (0..num_sym).map(|i| i as u8).collect();
        Self {
            sym,
            freq: vec![1u16; num_sym],
            total: num_sym as u32,
        }
    }

    /// The next symbol, and the model learns it.
    ///
    /// `None` when the code falls outside the model's range, which is a
    /// frame this reader cannot decode.
    ///
    /// Shared with the fqzcomp codec of CRAM 3.1.
    pub(crate) fn decode(&mut self, rc: &mut RangeCoder<'_, '_>) -> Option<u8> {
        let freq = rc.get_freq(self.total)?;
        // The symbol is the one whose share of the range holds the
        // cumulative frequency the code falls into.
        let mut x = 0usize;
        let mut acc = 0u32;
        while x < self.freq.len() {
            let f = u32::from(self.freq[x]);
            if acc + f > freq {
                break;
            }
            acc += f;
            x += 1;
        }
        if x >= self.freq.len() {
            // The code is past the last symbol of the model.
            return None;
        }
        rc.decode(acc, u32::from(self.freq[x]))?;
        // The model learns: the symbol's frequency grows by the step, and
        // the model is halved when its total grows too large.
        self.freq[x] += STEP;
        self.total += u32::from(STEP);
        if self.total > MAX_FREQ {
            self.renormalise();
        }
        let sym = self.sym[x];
        // The model keeps its symbols roughly sorted: a symbol that grew
        // past its predecessor swaps with it.
        if x > 0 && self.freq[x] > self.freq[x - 1] {
            self.freq.swap(x, x - 1);
            self.sym.swap(x, x - 1);
        }
        Some(sym)
    }

    /// Halve the frequencies, keeping every symbol's frequency at one.
    fn renormalise(&mut self) {
        self.total = 0;
        for f in self.freq.iter_mut() {
            *f -= *f / 2;
            self.total += u32::from(*f);
        }
    }
}

/// The number of symbols of the alphabet.
///
/// The specification reads it as a byte, where zero means the whole 256.
#[cfg(feature = "cram")]
fn read_num_sym(reader: &mut Reader<'_>) -> Option<usize> {
    let n = reader.byte()?;
    Some(if n == 0 { 256 } else { usize::from(n) })
}

/// The entropy-coded stream of section 4.2: order-0 and order-1.
///
/// The order-1 variant keeps a model per context, and the context is the
/// previous symbol.
#[cfg(feature = "cram")]
fn decode_order(reader: &mut Reader<'_>, len: usize, order1: bool) -> Option<Vec<u8>> {
    let num_sym = read_num_sym(reader)?;
    let mut lit = Model::new(num_sym);
    let mut contexts = if order1 {
        Some(vec![Model::new(num_sym); num_sym])
    } else {
        None
    };
    let mut rc = RangeCoder::new(reader)?;
    let mut out = vec![0u8; len];
    let mut last = 0u8;
    for byte in out.iter_mut() {
        let sym = match contexts.as_mut() {
            Some(models) => models[usize::from(last)].decode(&mut rc)?,
            None => lit.decode(&mut rc)?,
        };
        *byte = sym;
        last = sym;
    }
    Some(out)
}

/// The run-length coded stream of section 4.3.
///
/// The literals and the run lengths have models of their own: the run
/// length of a literal is coded in the context of that literal, the first
/// continuation in the context 256 and the rest in the context 257.
#[cfg(feature = "cram")]
fn decode_rle(reader: &mut Reader<'_>, len: usize, order1: bool) -> Option<Vec<u8>> {
    let num_sym = read_num_sym(reader)?;
    let mut lit = Model::new(num_sym);
    let mut contexts = if order1 {
        Some(vec![Model::new(num_sym); num_sym])
    } else {
        None
    };
    let mut runs: Vec<Model> = (0..RUN_MODELS).map(|_| Model::new(4)).collect();
    let mut rc = RangeCoder::new(reader)?;
    let mut out = vec![0u8; len];
    let mut i = 0usize;
    let mut last = 0u8;
    while i < len {
        let sym = match contexts.as_mut() {
            Some(models) => models[usize::from(last)].decode(&mut rc)?,
            None => lit.decode(&mut rc)?,
        };
        out[i] = sym;
        // The run that follows the literal. A length of three says that
        // another length follows and is added to this one.
        let mut ctx = usize::from(sym);
        let mut part = runs[ctx].decode(&mut rc)?;
        let mut run = usize::from(part);
        while part == RUN_CONTINUE {
            let next = if ctx == usize::from(sym) {
                RUN_CTX_FIRST
            } else {
                RUN_CTX_NEXT
            };
            part = runs[next].decode(&mut rc)?;
            ctx = next;
            run = run.saturating_add(usize::from(part));
        }
        // A run that does not fit the block is a frame this reader cannot
        // decode: the specification's pseudocode writes past the end of the
        // output there, and a block that is short of what it says it holds
        // is not decoded at all.
        if run.saturating_add(1) > len - i {
            return None;
        }
        out[i + 1..i + 1 + run].fill(sym);
        i += run + 1;
        last = sym;
    }
    Some(out)
}

/// The bit-packing meta-data of section 3.5: the map from a packed value to
/// the symbol it stands for.
#[cfg(feature = "cram")]
struct PackMeta {
    /// The symbol each packed value stands for.
    map: Vec<u8>,
    /// The number of bits a packed value takes: 1, 2 or 4. Zero is a stream
    /// of a single symbol, which is not packed at all.
    bits: u8,
}

#[cfg(feature = "cram")]
impl PackMeta {
    /// The meta-data of the frame: the number of distinct symbols, then the
    /// map itself.
    ///
    /// The specification does not permit more than sixteen distinct
    /// symbols, and none at all: bit packing needs at least one.
    fn read(reader: &mut Reader<'_>) -> Option<Self> {
        let nsym = reader.byte()?;
        if nsym == 0 || nsym > 16 {
            return None;
        }
        let mut map = Vec::with_capacity(usize::from(nsym));
        for _ in 0..nsym {
            map.push(reader.byte()?);
        }
        let bits = match nsym {
            1 => 0,
            2 => 1,
            3..=4 => 2,
            _ => 4,
        };
        Some(Self { map, bits })
    }
}

/// Unpack the data of a packed frame.
///
/// The packed values are read from the low bits of each byte upwards, and
/// each one is mapped back to the symbol it stands for.
#[cfg(feature = "cram")]
fn unpack(data: &[u8], len: usize, meta: &PackMeta) -> Option<Vec<u8>> {
    let mut out = vec![0u8; len];
    if meta.bits == 0 {
        // A stream of a single symbol: the data itself is empty.
        out.fill(*meta.map.first()?);
        return Some(out);
    }
    let mask = (1u8 << meta.bits) - 1;
    let per_byte = 8 / usize::from(meta.bits);
    let mut value = 0u8;
    for (at, byte) in out.iter_mut().enumerate() {
        if at.is_multiple_of(per_byte) {
            value = *data.get(at / per_byte)?;
        }
        *byte = *meta.map.get(usize::from(value & mask))?;
        value >>= meta.bits;
    }
    Some(out)
}

/// The external codec of section 4.4: bzip2.
///
/// The specification checks the magic number of the external codec before
/// it decodes with it; the bzip2 decoder of the core checks the same magic.
#[cfg(feature = "cram")]
fn decode_ext(data: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut decoder = Bzip2Decoder::new();
    let bounded = decoder.decode_bounded(data, len as u64).ok()?;
    if bounded.capped || bounded.bytes.len() != len {
        // The stream holds more than the frame says, or less.
        return None;
    }
    Some(bounded.bytes)
}

/// The interleaving of sub-streams of section 4.4.
///
/// The sub-streams are frames of this same shape, each with its own flag
/// byte, and the block is the bytes of the sub-streams interleaved: the
/// first byte of each in turn, then the second of each, and so on.
#[cfg(feature = "cram")]
fn decode_stripe(
    reader: &mut Reader<'_>,
    known_len: Option<usize>,
    depth: usize,
) -> Option<Vec<u8>> {
    // A sub-stream of a stripe may itself claim the stripe flag, and each
    // nesting level costs four bytes of the block: unbounded, a small
    // crafted block nests until the stack goes. Stripes do not
    // legitimately nest at all, so the depth bound is generous.
    if depth > 8 {
        return None;
    }
    // The stripe frame always carries the length of the whole block: the
    // sub-streams do not, and their lengths are fractions of it.
    let len = reader.uint7()? as usize;
    if let Some(want) = known_len {
        if want != len {
            return None;
        }
    }
    if len > MAX_OUTPUT {
        return None;
    }
    let n = reader.byte()? as usize;
    if n == 0 {
        // A stripe of no streams holds nothing.
        return None;
    }
    let mut clens = Vec::with_capacity(n);
    for _ in 0..n {
        let c = reader.uint7()? as usize;
        if c == 0 {
            return None;
        }
        clens.push(c);
    }
    // The j-th sub-stream holds every n-th byte of the block, and the first
    // (len mod n) of them hold one byte more than the rest.
    let mut streams = Vec::with_capacity(n);
    for &clen in &clens {
        let bytes = reader.bytes(clen)?;
        let ulen = len / n + usize::from(len % n > streams.len());
        let mut sub = Reader::new(bytes);
        streams.push(decode_frame(&mut sub, Some(ulen), depth + 1)?);
    }
    let mut out = vec![0u8; len];
    for (j, stream) in streams.iter().enumerate() {
        for (i, byte) in stream.iter().enumerate() {
            let slot = out.get_mut(i * n + j)?;
            *slot = *byte;
        }
    }
    Some(out)
}

/// Decode one frame.
///
/// `known_len` is the length of the uncompressed data when the frame does
/// not carry it, which is the case of the sub-streams of a stripe frame.
#[cfg(feature = "cram")]
fn decode_frame(
    reader: &mut Reader<'_>,
    known_len: Option<usize>,
    depth: usize,
) -> Option<Vec<u8>> {
    let flags = reader.byte()?;
    if flags & flag::RESERVED != 0 {
        // The specification reserves the second bit of the flag byte.
        return None;
    }
    if flags & flag::STRIPE != 0 {
        return decode_stripe(reader, known_len, depth);
    }
    // The length of the uncompressed data, unless the frame does not carry
    // it: then the caller has to know it.
    let len = if flags & flag::NOSIZE != 0 {
        known_len?
    } else {
        let len = reader.uint7()? as usize;
        if let Some(want) = known_len {
            if want != len {
                return None;
            }
        }
        len
    };
    if len > MAX_OUTPUT {
        return None;
    }
    // The bit-packing meta-data, when the frame carries it. The length that
    // follows it is the length of the packed data, which is what the
    // entropy-coded stream holds.
    let pack = if flags & flag::PACK != 0 {
        let meta = PackMeta::read(reader)?;
        let packed = reader.uint7()? as usize;
        if packed > MAX_OUTPUT {
            return None;
        }
        Some((meta, packed))
    } else {
        None
    };
    let data_len = match &pack {
        Some((_, packed)) => *packed,
        None => len,
    };
    // The order the specification decodes in: the stripe first, then the
    // stored bytes, then the external codec, then the run lengths, and
    // then the plain entropy coding.
    let data = if flags & flag::CAT != 0 {
        reader.bytes(data_len)?.to_vec()
    } else if flags & flag::EXT != 0 {
        decode_ext(reader.rest(), data_len)?
    } else if flags & flag::RLE != 0 {
        decode_rle(reader, data_len, flags & flag::ORDER != 0)?
    } else {
        decode_order(reader, data_len, flags & flag::ORDER != 0)?
    };
    match pack {
        // The bit-packing is undone after the entropy coding.
        Some((meta, _)) => unpack(&data, len, &meta),
        None => Some(data),
    }
}

/// Decode an arith-coded block of CRAM 3.1.
///
/// The block's bytes are the codec's own frame: the flag byte, the length of
/// the uncompressed data and the data itself. The flag byte says what the
/// data is, and the frame is decoded as the specification's `ArithDecode`
/// says: the stored bytes, the bzip2 stream, the run-length coded stream or
/// the entropy-coded stream, with the bit-packing undone last.
///
/// `None` when the frame is not one this reader can decode: a flag byte
/// with the reserved bit set, a frame that does not carry the length of its
/// data, a length that does not match the frame, a frame that ends before
/// the bytes it says it holds, a model whose code falls outside its range,
/// a run that does not fit the block, a bit-packed frame with no distinct
/// symbol or with more than sixteen, and a bzip2 stream that does not
/// decode to the length the frame says.
#[cfg(feature = "cram")]
pub(crate) fn decode(block: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(block);
    decode_frame(&mut reader, None, 0)
}

#[cfg(all(test, feature = "cram"))]
pub(crate) const ORDER0: &[u8] = &[
    0x00, 0x2d, 0x73, 0x00, 0xd9, 0xe2, 0x74, 0x43, 0x14, 0xfb, 0x9a, 0x2f, 0xa5, 0x1e, 0x10, 0x8c,
    0xeb, 0xd8, 0x9c, 0xfa, 0x3b, 0xed, 0x5f, 0xbe, 0x3a,
];

#[cfg(all(test, feature = "cram"))]
mod tests {
    use super::*;

    /// The frame of order-0 entropy coding, written by the reference
    /// implementation of the codec.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 0 <out>` over the 45 bytes of
    /// "abracadabraabracadabraabracadabraabracadabrad". The frame is the
    /// flag byte, the length of the data and the coded bytes, and the first
    /// byte of the coded part is the size of the alphabet.
    ///
    /// The frame of order-1 entropy coding, written by the reference
    /// implementation over the same 45 bytes.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 1 <out>`.
    #[cfg(all(test, feature = "cram"))]
    const ORDER1: &[u8] = &[
        0x01, 0x2d, 0x73, 0x00, 0xd9, 0xd8, 0xc6, 0x3b, 0x98, 0x81, 0xbe, 0xd6, 0x63, 0x9c, 0x4d,
        0x42, 0x11, 0xa9, 0x73, 0x5e, 0x4d, 0x1e, 0x51, 0xe1, 0x6f, 0x00,
    ];

    /// The frame of the stored bytes, written by the reference
    /// implementation over "abracadabra".
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 32 <out>`. The frame is the
    /// flag byte, the length and the bytes themselves.
    #[cfg(all(test, feature = "cram"))]
    const CAT: &[u8] = &[
        0x20, 0x0b, 0x61, 0x62, 0x72, 0x61, 0x63, 0x61, 0x64, 0x61, 0x62, 0x72, 0x61,
    ];

    /// The frame of order-0 run-length coding, written by the reference
    /// implementation over the same 45 bytes.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 64 <out>`.
    #[cfg(all(test, feature = "cram"))]
    const RLE0: &[u8] = &[
        0x40, 0x2d, 0x73, 0x00, 0xd8, 0x6a, 0x71, 0x16, 0x4e, 0x17, 0xd8, 0xa4, 0x7b, 0x2e, 0xb7,
        0xfb, 0x6d, 0xc5, 0x24, 0xef, 0xe8, 0x03, 0x52, 0xa4, 0xfa, 0x55, 0x22, 0xb0,
    ];

    /// The frame of order-1 run-length coding, written by the reference
    /// implementation over the same 45 bytes.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 65 <out>`.
    #[cfg(all(test, feature = "cram"))]
    const RLE1: &[u8] = &[
        0x41, 0x2d, 0x73, 0x00, 0xd8, 0x67, 0xe8, 0x1d, 0x0e, 0x19, 0x2a, 0x5f, 0xbb, 0xc3, 0x42,
        0x10, 0xd1, 0xa4, 0x78, 0x9b, 0xd2, 0x2d, 0x89, 0x86, 0xfb, 0x13, 0xf2,
    ];

    /// The frame of the run-length example of the specification, written by
    /// the reference implementation over "ABBCCCCDDDDD".
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 64 <out>`.
    #[cfg(all(test, feature = "cram"))]
    const RLE_SPEC: &[u8] = &[
        0x40, 0x0c, 0x45, 0x00, 0xf2, 0x0f, 0x44, 0x9c, 0x5d, 0x10, 0x5b, 0x6c, 0x00,
    ];

    /// The frame of a run-length coded block with a long run, written by the
    /// reference implementation.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 64 <out>` over 300 'A's,
    /// 17 'B's, "CCCC", five 'z's and "ABABAB". The run of 300 is longer
    /// than one run length can hold, so the continuation contexts 256 and
    /// 257 are used.
    #[cfg(all(test, feature = "cram"))]
    const RLE_RUNS: &[u8] = &[
        0x40, 0x82, 0x4c, 0x7b, 0x00, 0x89, 0x59, 0xab, 0x3c, 0xe1, 0x9d, 0xbb, 0x2d, 0xc7, 0x7a,
        0x11, 0xf4, 0x70, 0x68, 0xb3, 0x0f, 0x00,
    ];

    /// The frame of an interleaving of four sub-streams, written by the
    /// reference implementation over the same 45 bytes.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 8 <out>`. The frame is the
    /// flag byte, the length of the whole block, the number of sub-streams,
    /// the length of each of them and the sub-streams themselves. The
    /// sub-streams are frames of this same shape, and the reference
    /// implementation chose a stored one for the first and a bit-packed one
    /// for the third and the fourth.
    #[cfg(all(test, feature = "cram"))]
    const STRIPE4: &[u8] = &[
        0x08, 0x2d, 0x04, 0x0d, 0x0c, 0x0e, 0x0e, 0x70, 0x61, 0x63, 0x62, 0x62, 0x61, 0x72, 0x72,
        0x64, 0x61, 0x61, 0x61, 0x64, 0x30, 0x62, 0x61, 0x72, 0x72, 0x64, 0x61, 0x61, 0x61, 0x61,
        0x63, 0x62, 0xb0, 0x05, 0x61, 0x62, 0x63, 0x64, 0x72, 0x06, 0x34, 0x00, 0x00, 0x12, 0x01,
        0x04, 0xb0, 0x05, 0x61, 0x62, 0x63, 0x64, 0x72, 0x06, 0x00, 0x20, 0x11, 0x40, 0x34, 0x00,
    ];

    /// The frame of an interleaving of three sub-streams, written by the
    /// reference implementation over the same 45 bytes.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 776 <out>`, where the high
    /// byte of the flag byte holds the number of sub-streams.
    #[cfg(all(test, feature = "cram"))]
    const STRIPE3: &[u8] = &[
        0x08, 0x2d, 0x03, 0x0f, 0x0f, 0x10, 0x10, 0x73, 0x00, 0xd9, 0xd2, 0xb8, 0x26, 0xec, 0x2a,
        0xd5, 0x76, 0x8b, 0x6f, 0xe3, 0x00, 0x10, 0x73, 0x00, 0xdc, 0x20, 0x3e, 0xdf, 0x5e, 0x92,
        0x9d, 0xb7, 0xc7, 0xe4, 0xb9, 0x00, 0xb0, 0x05, 0x61, 0x62, 0x63, 0x64, 0x72, 0x08, 0x04,
        0x01, 0x30, 0x14, 0x02, 0x40, 0x10, 0x03,
    ];

    /// The frame of a bit-packed block, written by the reference
    /// implementation over 160 bytes of the four values 0, 1, 2 and 3.
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 128 <out>`. The frame is the
    /// flag byte, the length of the block, the packing meta-data (the four
    /// distinct symbols and their map), the length of the packed data and
    /// the packed data itself, entropy-coded.
    #[cfg(all(test, feature = "cram"))]
    const PACK: &[u8] = &[
        0x80, 0x81, 0x20, 0x04, 0x00, 0x01, 0x02, 0x03, 0x28, 0xe5, 0x00, 0xff, 0xfe, 0xa3, 0xfb,
        0x25, 0xdd, 0xf9, 0x8d, 0x39, 0x59,
    ];

    /// The frame of a bit-packed block that was stored as it is, written by
    /// the reference implementation over "abracadabra".
    ///
    /// The oracle: `/tmp/arithref/arithref <in> 128 <out>`. The five
    /// distinct symbols of the block are packed two to a byte, and the
    /// packed bytes are small enough that the reference implementation
    /// stored them instead of coding them.
    #[cfg(all(test, feature = "cram"))]
    const PACK_CAT: &[u8] = &[
        0xa0, 0x0b, 0x05, 0x61, 0x62, 0x63, 0x64, 0x72, 0x06, 0x10, 0x04, 0x02, 0x03, 0x41, 0x00,
    ];

    /// The 45 bytes the frames above were written from.
    fn abracadabra45() -> Vec<u8> {
        b"abracadabraabracadabraabracadabraabracadabrad".to_vec()
    }

    /// The 332 bytes the long-run frame was written from.
    fn long_runs() -> Vec<u8> {
        let mut out = vec![b'A'; 300];
        out.extend_from_slice(&[b'B'; 17]);
        out.extend_from_slice(b"CCCC");
        out.extend_from_slice(&[b'z'; 5]);
        out.extend_from_slice(b"ABABAB");
        out
    }

    /// The order-0 frame of the reference implementation decodes back to
    /// the bytes it was written from.
    #[test]
    fn the_order0_frame_of_the_reference_implementation_decodes() {
        assert_eq!(
            decode(ORDER0).as_deref(),
            Some(abracadabra45().as_slice()),
            "the order-0 frame is not decoded"
        );
    }

    /// The order-1 frame of the reference implementation decodes back to
    /// the bytes it was written from.
    #[test]
    fn the_order1_frame_of_the_reference_implementation_decodes() {
        assert_eq!(
            decode(ORDER1).as_deref(),
            Some(abracadabra45().as_slice()),
            "the order-1 frame is not decoded"
        );
    }

    /// The stored frame of the reference implementation decodes back to the
    /// bytes it was written from.
    #[test]
    fn the_stored_frame_of_the_reference_implementation_decodes() {
        assert_eq!(
            decode(CAT).as_deref(),
            Some(&b"abracadabra"[..]),
            "the stored frame is not decoded"
        );
    }

    /// The two run-length frames of the reference implementation decode
    /// back to the bytes they were written from.
    #[test]
    fn the_run_length_frames_of_the_reference_implementation_decode() {
        assert_eq!(
            decode(RLE0).as_deref(),
            Some(abracadabra45().as_slice()),
            "the order-0 run-length frame is not decoded"
        );
        assert_eq!(
            decode(RLE1).as_deref(),
            Some(abracadabra45().as_slice()),
            "the order-1 run-length frame is not decoded"
        );
    }

    /// The run-length frame of the specification's own example decodes back
    /// to "ABBCCCCDDDDD", where the run of four 'C's and the run of five
    /// 'D's are the runs the section is about.
    #[test]
    fn the_run_length_frame_of_the_specification_example_decodes() {
        assert_eq!(
            decode(RLE_SPEC).as_deref(),
            Some(&b"ABBCCCCDDDDD"[..]),
            "the run-length frame of the example is not decoded"
        );
    }

    /// The run-length frame of a long run decodes back to the bytes it was
    /// written from, which exercises the continuation contexts of the run
    /// lengths.
    #[test]
    fn the_run_length_frame_of_a_long_run_decodes() {
        assert_eq!(
            decode(RLE_RUNS).as_deref(),
            Some(long_runs().as_slice()),
            "the run-length frame of the long run is not decoded"
        );
    }

    /// The two interleaved frames of the reference implementation decode
    /// back to the bytes they were written from. The sub-streams of these
    /// frames are stored and bit-packed ones, so the frame is decoded by
    /// more than one path.
    #[test]
    fn the_interleaved_frames_of_the_reference_implementation_decode() {
        assert_eq!(
            decode(STRIPE4).as_deref(),
            Some(abracadabra45().as_slice()),
            "the frame of four sub-streams is not decoded"
        );
        assert_eq!(
            decode(STRIPE3).as_deref(),
            Some(abracadabra45().as_slice()),
            "the frame of three sub-streams is not decoded"
        );
    }

    /// The two bit-packed frames of the reference implementation decode
    /// back to the bytes they were written from.
    #[test]
    fn the_bit_packed_frames_of_the_reference_implementation_decode() {
        let mut want = Vec::new();
        for _ in 0..40 {
            want.extend_from_slice(&[0, 1, 2, 3]);
        }
        assert_eq!(
            decode(PACK).as_deref(),
            Some(want.as_slice()),
            "the bit-packed frame is not decoded"
        );
        assert_eq!(
            decode(PACK_CAT).as_deref(),
            Some(&b"abracadabra"[..]),
            "the bit-packed frame that is stored is not decoded"
        );
    }

    /// A frame this reader cannot decode is refused, not guessed at.
    #[test]
    fn a_frame_that_is_not_one_this_reader_can_decode_is_refused() {
        // A flag byte with the reserved bit set: the specification defines
        // no codec for it.
        let mut frame = ORDER0.to_vec();
        frame[0] = 0x02;
        assert!(decode(&frame).is_none(), "the reserved bit was not refused");

        // A frame that does not carry the length of its data: nothing says
        // how long the block is.
        let mut frame = ORDER0.to_vec();
        frame[0] = 0x10;
        assert!(
            decode(&frame).is_none(),
            "the frame without a length was not refused"
        );

        // A frame that ends before the bytes it says it holds.
        let frame = &ORDER0[..ORDER0.len() - 4];
        assert!(decode(frame).is_none(), "the short frame was not refused");

        // A frame whose length does not match the data: the length says 45
        // bytes and the frame holds fewer.
        let mut frame = ORDER0.to_vec();
        frame[1] = 0x2e;
        assert!(decode(&frame).is_none(), "the wrong length was not refused");

        // A frame whose alphabet is larger than the symbols it can hold.
        let mut frame = ORDER0.to_vec();
        frame[2] = 0x00;
        assert!(
            decode(&frame).is_none(),
            "the wrong alphabet was not refused"
        );

        // A frame that is too short to hold its own flag byte.
        assert!(decode(&[]).is_none(), "the empty frame was not refused");
        assert!(decode(&[0x00]).is_none(), "the stub was not refused");
    }

    /// A bit-packed frame with no distinct symbol, or with more than
    /// sixteen, is refused: the specification does not permit either.
    #[test]
    fn a_bit_packed_frame_that_cannot_be_packed_is_refused() {
        // The meta-data says there is no distinct symbol.
        let mut frame = PACK.to_vec();
        frame[3] = 0x00;
        assert!(
            decode(&frame).is_none(),
            "the frame with no distinct symbol was not refused"
        );

        // The meta-data says there are seventeen.
        let mut frame = PACK.to_vec();
        frame[3] = 0x11;
        assert!(
            decode(&frame).is_none(),
            "the frame with seventeen symbols was not refused"
        );
    }

    /// An interleaved frame with no sub-streams, or with a sub-stream of no
    /// bytes, is refused.
    #[test]
    fn an_interleaved_frame_that_does_not_hold_its_streams_is_refused() {
        // No sub-streams at all.
        let mut frame = STRIPE4.to_vec();
        frame[2] = 0x00;
        assert!(
            decode(&frame).is_none(),
            "the frame with no sub-streams was not refused"
        );

        // A sub-stream of no bytes.
        let mut frame = STRIPE4.to_vec();
        frame[3] = 0x00;
        assert!(
            decode(&frame).is_none(),
            "the frame with an empty sub-stream was not refused"
        );
    }

    /// A frame this reader cannot decode does not make it panic: the reader
    /// is handed bytes it did not choose, and the answer to the ones it
    /// cannot decode is a refusal, not a crash.
    #[test]
    fn a_frame_that_cannot_be_decoded_does_not_make_the_reader_panic() {
        for len in 0..64usize {
            let bytes = pseudo_random(len);
            let _ = decode(&bytes);
        }
        // The frames of the reference implementation, with one byte changed
        // at a time.
        let frames: [&[u8]; 11] = [
            ORDER0, ORDER1, CAT, RLE0, RLE1, RLE_SPEC, RLE_RUNS, STRIPE4, STRIPE3, PACK, PACK_CAT,
        ];
        for frame in frames {
            for at in 0..frame.len() {
                for value in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                    let mut mutated = frame.to_vec();
                    mutated[at] = value;
                    let _ = decode(&mutated);
                }
            }
        }
    }

    /// The bytes of a pseudo-random sequence, the same on every run.
    fn pseudo_random(count: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push((state & 0xff) as u8);
        }
        out
    }
}
