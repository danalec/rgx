// SPDX-License-Identifier: Apache-2.0

//! RFC 7932 Section 1.5.1 bit packing, and Section 3 prefix codes.
//!
//! Brotli packs bits into bytes least-significant first (§1.5.1): the
//! first bit of the stream is bit 0 of byte 0. Every multi-bit integer in
//! the format is written the same way, so a "read 3 bits" means "take the
//! next three stream bits, the first of which is the integer's low bit".
//! Prefix *codes* run the other way and are reversed when the decoding
//! table is built, which is why [`PrefixCode::read`] says so where it
//! happens.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::error::{Error, Result};

/// The compressed stream, read as a bit cursor over the whole input.
///
/// A decode is a single pass over a buffer already in memory, so the cursor
/// is a bit offset and nothing more. `peek` past the end reads zeroes,
/// which is what the last symbol of the last meta-block needs when a
/// Huffman code is shorter than the byte it lands in; `take` is what turns
/// a read genuinely past the end into an error.
pub struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// `n` bits starting `at` bits from the cursor, zero-filled past the
    /// end of the input. `n` <= 24.
    fn peek_at(&self, at: usize, n: u32) -> u32 {
        let pos = self.pos + at;
        let byte = pos >> 3;
        let mut acc = [0u8; 4];
        for (i, slot) in acc.iter_mut().enumerate() {
            *slot = self.data.get(byte + i).copied().unwrap_or(0);
        }
        (u32::from_le_bytes(acc) >> (pos & 7)) & ((1u32 << n) - 1)
    }

    /// The next `n` bits, without consuming them. `n` <= 24.
    pub fn peek(&self, n: u32) -> u32 {
        self.peek_at(0, n)
    }

    /// Consume `n` bits. `n` <= 24.
    pub fn take(&mut self, n: u32) -> Result<u32> {
        let v = self.peek_at(0, n);
        self.pos += n as usize;
        if self.pos > self.data.len() * 8 {
            return Err(Error::Truncated);
        }
        Ok(v)
    }

    pub fn bit(&mut self) -> Result<u32> {
        self.take(1)
    }

    /// Consume up to the next byte boundary. The bits skipped are padding
    /// and §9.2 requires them to be zero.
    pub fn align(&mut self) -> Result<()> {
        let pad = (8 - (self.pos & 7)) & 7;
        if pad != 0 && self.take(pad as u32)? != 0 {
            return Err(Error::Padding);
        }
        Ok(())
    }

    /// Skip `n` whole bytes, which is how a stored meta-block and a
    /// metadata block hand their payload over.
    pub fn skip_bytes(&mut self, n: usize) -> Result<()> {
        let n = n * 8;
        self.pos += n;
        if self.pos > self.data.len() * 8 {
            return Err(Error::Truncated);
        }
        Ok(())
    }

    /// The next `n` whole bytes, and step over them. This is the stored
    /// meta-block path, where the payload is not a bit field at all.
    pub fn take_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let at = self.pos / 8;
        let end = at.checked_add(n).ok_or(Error::Truncated)?;
        if end > self.data.len() {
            return Err(Error::Truncated);
        }
        self.pos = end * 8;
        Ok(&self.data[at..end])
    }
}

/// A canonical prefix code, decoded through a two-level table.
///
/// The root covers the first 8 bits; anything longer lands in a sub-table
/// indexed by the next 7. 8 + 7 is 15, the longest code RFC 7932 allows,
/// so two levels always suffice. A sub-table is shared by every code that
/// passes through the same 8-bit prefix, which is what keeps a meta-block
/// carrying 256 literal trees from costing 256 tables' worth of them.
pub struct PrefixCode {
    /// `Some` when the code is a single symbol occupying no bits: §3.4
    /// with NSYM = 1, and the degenerate code of §3.5.
    single: Option<u16>,
    root: Box<[Entry; 256]>,
    sub: Vec<Box<[Entry]>>,
}

/// One table slot. `bits == 0` is a slot no code reached. `bits` with
/// [`LEAF`] set is a finished code of `bits & !LEAF` bits carrying
/// `value`. Anything else is a sub-table index, stored biased by one so
/// that zero can mean "empty".
#[derive(Clone, Copy)]
struct Entry {
    bits: u16,
    value: u16,
}

const ROOT_BITS: u32 = 8;
const SUB_BITS: u32 = 7;
const LEAF: u16 = 0x8000;

impl PrefixCode {
    /// A code that is not a code: every read of it is an error. For the
    /// alphabets a meta-block does not carry, so a caller that reaches one
    /// gets a refusal rather than a symbol zero.
    pub fn invalid() -> Self {
        Self {
            single: None,
            root: Box::new([Entry { bits: 0, value: 0 }; 256]),
            sub: Vec::new(),
        }
    }

    /// Read one prefix code over an alphabet of `alphabet_size` symbols
    /// (§3.4 and §3.5).
    pub fn read(bits: &mut Bits, alphabet_size: usize) -> Result<Self> {
        let hskip = bits.take(2)?;
        if hskip == 1 {
            #[cfg(test)]
            super::coverage::bump(&super::coverage::SIMPLE);
            Self::read_simple(bits, alphabet_size)
        } else {
            #[cfg(test)]
            super::coverage::bump(&super::coverage::COMPLEX);
            Self::read_complex(bits, alphabet_size, hskip)
        }
    }

    /// §3.4: at most four symbols, read at the alphabet's own width.
    fn read_simple(bits: &mut Bits, alphabet_size: usize) -> Result<Self> {
        let nsym = bits.take(2)? as usize + 1;
        // "The value of ALPHABET_BITS ... is the smallest number of bits
        // that can represent all symbols in the alphabet" -- 8 for the
        // 256-symbol literal alphabet, 5 for the 26-symbol block count
        // alphabet, and so on.
        let width = bits_for(alphabet_size);
        let mut syms = [(0u16, 0u8); 4];
        for sym in syms.iter_mut().take(nsym) {
            let v = bits.take(width)?;
            if v as usize >= alphabet_size {
                return Err(Error::Symbol);
            }
            *sym = (v as u16, 0);
        }
        // "If ... the value is identical to a previous value, then the
        // stream should be rejected as invalid."
        for i in 1..nsym {
            if syms[..i].iter().any(|(s, _)| *s == syms[i].0) {
                return Err(Error::Symbol);
            }
        }
        // §3.4: "if NSYM = 1, the code length for the one symbol is zero --
        // when encoding this symbol in the compressed data stream using
        // this prefix code, no actual bits are emitted." A code with
        // nothing but that symbol is not a prefix code at all, so it is
        // built directly rather than through the canonical construction.
        if nsym == 1 {
            #[cfg(test)]
            super::coverage::bump(&super::coverage::SINGLETON);
            let mut only = PrefixCode::invalid();
            only.single = Some(syms[0].0);
            return Ok(only);
        }
        let lengths: [u8; 4] = match nsym {
            2 => [1, 1, 0, 0],
            3 => [1, 2, 2, 0],
            // The tree-select bit is present only for NSYM = 4, and is
            // the last thing this code reads.
            _ => {
                if bits.bit()? == 0 {
                    [2, 2, 2, 2]
                } else {
                    [1, 2, 3, 3]
                }
            }
        };
        for (entry, len) in syms.iter_mut().zip(lengths) {
            entry.1 = len;
        }
        Self::build(&syms[..nsym])
    }

    /// §3.5: the code lengths are themselves prefix-coded, over an 18
    /// symbol alphabet that adds two repeat codes on top.
    fn read_complex(bits: &mut Bits, alphabet_size: usize, hskip: u32) -> Result<Self> {
        const ORDER: [usize; 18] = [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut cl_lengths = [0u8; 18];
        let mut space = 32i32;
        let mut codes = 0;
        // Trailing zeros are omitted, so the loop ends when the code is
        // complete (space hits zero) rather than after 18 symbols.
        for &sym in &ORDER[hskip as usize..] {
            let len = read_cl_len(bits)?;
            cl_lengths[sym] = len;
            if len != 0 {
                codes += 1;
                space -= 32 >> len;
                if space <= 0 {
                    break;
                }
            }
        }
        if !(codes == 1 || space == 0) {
            return Err(Error::CodeLength);
        }
        let cl = Self::build(&all_pairs(cl_lengths))?;

        let mut lengths = vec![0u8; alphabet_size];
        let mut symbol = 0usize;
        let mut prev = 8u8;
        let mut repeat = 0u32;
        let mut repeat_len = 0u8;
        let mut space = 32768i32;
        while symbol < alphabet_size && space > 0 {
            let code_len = cl.decode(bits)? as u8;
            if code_len < 16 {
                lengths[symbol] = code_len;
                symbol += 1;
                if code_len != 0 {
                    prev = code_len;
                    space -= 32768 >> code_len;
                }
                repeat = 0;
                continue;
            }
            // 16 repeats the previous non-zero length 3..6 times, 17
            // repeats a zero 3..10. A run of the same repeat code
            // compounds onto the count the last one established, and a
            // different code resets it.
            let extra = code_len as u32 - 14;
            let new_len = if code_len == 16 { prev } else { 0 };
            if repeat_len != new_len {
                repeat = 0;
                repeat_len = new_len;
            }
            let before = repeat;
            if repeat > 0 {
                repeat = (repeat - 2) << extra;
            }
            repeat += bits.take(extra)? + 3;
            let added = repeat - before;
            if symbol + added as usize > alphabet_size {
                return Err(Error::CodeLength);
            }
            for _ in 0..added {
                lengths[symbol] = repeat_len;
                symbol += 1;
                if repeat_len != 0 {
                    space -= 32768 >> repeat_len;
                }
            }
        }
        if space != 0 {
            return Err(Error::CodeLength);
        }
        let pairs: Vec<(u16, u8)> = lengths
            .iter()
            .enumerate()
            .map(|(i, &l)| (i as u16, l))
            .collect();
        Self::build(&pairs)
    }

    /// Build a canonical code from explicit (symbol, length) pairs (§3.2).
    /// Pair order does not matter: §3.2 assigns codes to symbols of equal
    /// length in symbol order, which is what makes the representation
    /// canonical.
    fn build(pairs: &[(u16, u8)]) -> Result<Self> {
        let mut code = PrefixCode::invalid();
        let mut counts = [0u16; 16];
        let mut used = 0usize;
        let mut space = 0i32;
        for &(_, len) in pairs {
            if len as usize >= 16 {
                return Err(Error::CodeLength);
            }
            if len != 0 {
                counts[len as usize] += 1;
                used += 1;
                space += 32768 >> len;
            }
        }
        if used == 0 {
            return Err(Error::CodeLength);
        }
        if used == 1 {
            // A single symbol whose code occupies no bits. §3.5 reaches
            // this when the whole code is one repeated length, e.g. every
            // literal eight bits wide.
            #[cfg(test)]
            super::coverage::bump(&super::coverage::SINGLETON);
            let only = pairs.iter().find(|(_, l)| *l != 0).map(|(s, _)| *s);
            code.single = only;
            return Ok(code);
        }
        // A prefix code has to be complete: it must cover the code space
        // exactly, with no over- and no under-subscription.
        if space != 32768 {
            return Err(Error::CodeLength);
        }
        let mut ordered: Vec<(u8, u16)> = pairs
            .iter()
            .filter(|(_, l)| *l != 0)
            .map(|&(s, l)| (l, s))
            .collect();
        ordered.sort_unstable();
        // next_code[len] is the first code of that length (§3.2 step 2).
        let mut next_code = [0u16; 16];
        let mut c = 0u16;
        for len in 1..16usize {
            c = (c + counts[len - 1]) << 1;
            next_code[len] = c;
        }
        for (len, sym) in ordered {
            code.insert(sym, len, next_code[len as usize]);
            next_code[len as usize] += 1;
        }
        Ok(code)
    }

    /// Place one symbol. `code` is the canonical code, most significant bit
    /// first; the stream carries it in the opposite order (§3.2), so the
    /// table is indexed by the reversed code.
    fn insert(&mut self, sym: u16, len: u8, code: u16) {
        if len == 0 {
            return;
        }
        let rev = reverse(code as u32, len as u32) as usize;
        let leaf = Entry {
            bits: LEAF | len as u16,
            value: sym,
        };
        if len as u32 <= ROOT_BITS {
            let step = 1usize << len;
            for slot in self.root[rev..].iter_mut().step_by(step) {
                *slot = leaf;
            }
            return;
        }
        // The root is indexed by the eight bits just peeked, so a key is
        // exactly one slot -- and that slot is where the next code with
        // the same key finds the sub-table the first one made.
        let key = rev & 0xFF;
        let index = if self.root[key].bits == 0 {
            let index = self.sub.len();
            self.sub
                .push(vec![Entry { bits: 0, value: 0 }; 1 << SUB_BITS].into_boxed_slice());
            self.root[key] = Entry {
                bits: index as u16 + 1,
                value: 0,
            };
            index
        } else {
            self.root[key].bits as usize - 1
        };
        let table = &mut self.sub[index];
        let inner = (len as u32 - ROOT_BITS) as usize;
        let at = (rev >> ROOT_BITS) & ((1usize << SUB_BITS) - 1);
        let step = 1usize << inner;
        for slot in table[at..].iter_mut().step_by(step) {
            *slot = leaf;
        }
    }

    /// Read one symbol, consuming its code.
    pub fn decode(&self, bits: &mut Bits) -> Result<u16> {
        if let Some(sym) = self.single {
            return Ok(sym);
        }
        let slot = self.root[bits.peek(ROOT_BITS) as usize];
        if slot.bits & LEAF != 0 {
            let len = slot.bits & !LEAF;
            if len == 0 {
                return Err(Error::Code);
            }
            bits.take(len as u32)?;
            return Ok(slot.value);
        }
        if slot.bits == 0 {
            return Err(Error::Code);
        }
        let table = self.sub.get(slot.bits as usize - 1).ok_or(Error::Code)?;
        let sub = table[bits.peek_at(ROOT_BITS as usize, SUB_BITS) as usize];
        if sub.bits & LEAF == 0 {
            return Err(Error::Code);
        }
        let len = (sub.bits & !LEAF) as u32;
        if len == 0 {
            return Err(Error::Code);
        }
        bits.take(len)?;
        Ok(sub.value)
    }
}

/// The fixed variable-length code of §3.5 that carries the code length code
/// lengths: 0 is `00`, 4 is `01`, 3 is `10`, 2 is `011`, 1 is `0111` and 5
/// is `1111`, each written as it appears in the stream and so read
/// least-significant bit first.
fn read_cl_len(bits: &mut Bits) -> Result<u8> {
    Ok(match bits.take(2)? {
        0 => 0,
        1 => 4,
        2 => 3,
        _ => match bits.bit()? {
            0 => 2,
            _ => match bits.bit()? {
                0 => 1,
                _ => 5,
            },
        },
    })
}

/// (symbol, length) pairs for a full alphabet's worth of code lengths,
/// dropping the ones a code can never use.
fn all_pairs(lengths: [u8; 18]) -> Vec<(u16, u8)> {
    lengths
        .iter()
        .enumerate()
        .map(|(i, &l)| (i as u16, l))
        .collect()
}

/// The smallest number of bits that can hold every symbol of an alphabet
/// of `n` symbols: how wide a simple prefix code's symbols are.
fn bits_for(n: usize) -> u32 {
    let mut w = 0u32;
    while (1usize << w) < n {
        w += 1;
    }
    w.max(1)
}

fn reverse(mut v: u32, n: u32) -> u32 {
    let mut out = 0;
    for _ in 0..n {
        out = (out << 1) | (v & 1);
        v >>= 1;
    }
    out
}
