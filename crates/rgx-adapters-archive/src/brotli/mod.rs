// SPDX-License-Identifier: Apache-2.0

//! RFC 7932 Brotli decoder. Implements the full format: stream
//! header, meta-block headers, block switching, context maps, the
//! insert-and-copy command alphabet, backward references with the four
//! short distance codes, the static dictionary and its 121 word
//! transformations. Verified against files emitted by the reference
//! `brotli` CLI; see `testdata/brotli_README.md` for the vector list.

extern crate alloc;

mod context;
mod error;
mod prefix;
mod tables;

use alloc::vec;
use alloc::vec::Vec;

#[cfg(test)]
pub mod coverage {
    use std::sync::atomic::{AtomicUsize, Ordering};
    pub const N: usize = 121;
    pub static DICT_WORDS: AtomicUsize = AtomicUsize::new(0);
    pub static TRANSFORMS: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
    pub static SIMPLE: AtomicUsize = AtomicUsize::new(0);
    pub static COMPLEX: AtomicUsize = AtomicUsize::new(0);
    pub static SINGLETON: AtomicUsize = AtomicUsize::new(0);
    pub static STORED: AtomicUsize = AtomicUsize::new(0);
    pub static METADATA: AtomicUsize = AtomicUsize::new(0);
    pub static BLOCK_SWITCHES: AtomicUsize = AtomicUsize::new(0);
    pub static SHORT_DIST: [AtomicUsize; 16] = [const { AtomicUsize::new(0) }; 16];
    pub static DIRECT_DIST: AtomicUsize = AtomicUsize::new(0);
    pub static COMPUTED_DIST: AtomicUsize = AtomicUsize::new(0);
    pub static CONTEXT_MODES: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
    pub static CONTEXT_MAPS: AtomicUsize = AtomicUsize::new(0);
    pub static IMULTIPLE: AtomicUsize = AtomicUsize::new(0);
    pub static RLE_ZERO: AtomicUsize = AtomicUsize::new(0);
    pub static WINDOWS: [AtomicUsize; 25] = [const { AtomicUsize::new(0) }; 25];
    pub static METABLOCKS: AtomicUsize = AtomicUsize::new(0);
    pub fn bump(c: &AtomicUsize) {
        c.fetch_add(1, Ordering::Relaxed);
    }
    /// Zero every counter, so a test can measure the corpus itself
    /// rather than whatever the binary's other threads ran first.
    pub fn reset() {
        for c in [
            &DICT_WORDS,
            &SIMPLE,
            &COMPLEX,
            &SINGLETON,
            &STORED,
            &METADATA,
            &BLOCK_SWITCHES,
            &DIRECT_DIST,
            &COMPUTED_DIST,
            &CONTEXT_MAPS,
            &IMULTIPLE,
            &RLE_ZERO,
            &METABLOCKS,
        ] {
            c.store(0, Ordering::Relaxed);
        }
        for c in TRANSFORMS.iter() {
            c.store(0, Ordering::Relaxed);
        }
        for c in SHORT_DIST.iter() {
            c.store(0, Ordering::Relaxed);
        }
        for c in CONTEXT_MODES.iter() {
            c.store(0, Ordering::Relaxed);
        }
        for c in WINDOWS.iter() {
            c.store(0, Ordering::Relaxed);
        }
    }
    pub fn get(c: &AtomicUsize) -> usize {
        c.load(Ordering::Relaxed)
    }
}

pub use error::{Error, Result};
use rgx_core::compress::{Bounded, OutputCap};

use context::literal_context;

/// The literal context ID, re-exported for the test that pins all four
/// context modes: the reference encoder picks the mode, so the corpus
/// cannot be relied on to reach every one of them.
#[cfg(test)]
pub(crate) use context::literal_context as context_for_test;
use prefix::{Bits, PrefixCode};
use tables::Kind;

/// The largest backward distance the format can name. Past the maximum
/// allowed distance, a distance is a static dictionary word instead.
const MAX_DISTANCE: u64 = 0x7FFF_FFFC;
/// §8: static dictionary words are 4 to 24 bytes.
const MIN_WORD: usize = 4;
const MAX_WORD: usize = 24;
/// §8: a transformed word is the longest base word plus the most bytes
/// any transform adds, 13.
const TRANSFORM_BUFFER: usize = MAX_WORD + 13;

/// An RFC 7932 decoder.
///
/// Cheap to name rather than to carry around: every method takes `&self`
/// and builds its own state, because the whole stream is in memory either
/// way and there is nothing to keep between calls.
#[derive(Debug, Default)]
pub struct BrotliDecoder {
    _priv: (),
}

impl BrotliDecoder {
    pub const fn new() -> Self {
        Self { _priv: () }
    }

    /// Decode a whole `.br`, stopping at `limit` bytes.
    ///
    /// The cap is enforced as bytes are emitted rather than measured
    /// afterwards, so a bomb costs what the budget allows and no more.
    /// Brotli declares no content size anywhere in the container, so
    /// `Bounded::declared` is always `None`: there is nothing to say about
    /// how much was left out.
    pub fn decode_bounded(&self, data: &[u8], limit: u64) -> Result<Bounded> {
        let mut st = State {
            bits: Bits::new(data),
            out: Vec::new(),
            cap: OutputCap::new(limit),
            window: 0,
            p1: 0,
            p2: 0,
            // §4: the ring of last distances is seeded once per *stream*,
            // not per meta-block: fourth-to-last furthest back, last
            // nearest.
            dist_rb: [16, 15, 11, 4],
            dist_rb_idx: 0,
        };
        match st.run() {
            Ok(()) => Ok(Bounded::complete(st.out, None, limit)),
            Err(Error::Budget) => Ok(Bounded::stopped(st.out, None, limit)),
            Err(e) => Err(e),
        }
    }
}

/// Everything one decode carries from field to field.
struct State<'a> {
    bits: Bits<'a>,
    out: Vec<u8>,
    cap: OutputCap,
    /// The sliding window, `(1 << WBITS) - 16` (§9.1).
    window: u32,
    /// The last and second-to-last uncompressed bytes, which the literal
    /// context is computed from (§7.1). Seeded to zero.
    p1: u8,
    p2: u8,
    dist_rb: [u32; 4],
    dist_rb_idx: usize,
}

/// One block category's switching state (§6).
struct Blocks {
    /// The number of block types in the category, 1..256.
    nbltypes: usize,
    btype: usize,
    /// Blocks left before the next switch. 2^24 when there is only one
    /// block type, which is more commands than a meta-block can hold.
    blen: u32,
    /// "The block type that preceded the current type", seeded to 1 so
    /// that block type symbol 0 on the first switch means 1, not 0.
    prev: usize,
    btype_code: PrefixCode,
    blen_code: PrefixCode,
}

impl Blocks {
    /// §6: block type symbols 0 and 1 are relative -- "the type of the
    /// previous block" and "one past the current" -- and the rest are
    /// literal.
    fn switch(&mut self, bits: &mut Bits) -> Result<()> {
        #[cfg(test)]
        coverage::bump(&coverage::BLOCK_SWITCHES);
        let sym = self.btype_code.decode(bits)?;
        let next = match sym {
            0 => self.prev,
            1 => {
                if self.btype + 1 >= self.nbltypes {
                    0
                } else {
                    self.btype + 1
                }
            }
            other => (other - 2) as usize,
        };
        if next >= self.nbltypes {
            return Err(Error::Range);
        }
        self.prev = self.btype;
        self.btype = next;
        self.blen = read_blen(&self.blen_code, bits)?;
        Ok(())
    }
}

/// §6: the block count code, alphabet 26, with up to 24 extra bits.
const BLEN_BASE: [u32; 26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625,
];
const BLEN_EXTRA: [u32; 26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

fn read_blen(code: &PrefixCode, bits: &mut Bits) -> Result<u32> {
    let sym = code.decode(bits)? as usize;
    if sym >= 26 {
        return Err(Error::Symbol);
    }
    Ok(BLEN_BASE[sym] + bits.take(BLEN_EXTRA[sym])?)
}

/// §5: which insert length code and copy length code each 64-wide cell of
/// the insert-and-copy alphabet holds, in symbol order.
const SPLIT: [(u8, u8); 11] = [
    (0, 0),
    (0, 8),
    (0, 0),
    (0, 8),
    (8, 0),
    (8, 8),
    (0, 16),
    (16, 0),
    (8, 16),
    (16, 8),
    (16, 16),
];
const INSERT_BASE: [u32; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];
const INSERT_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];
const COPY_BASE: [u32; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];
const COPY_EXTRA: [u32; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];

/// One decoded command: how many literals to insert, how many bytes to
/// copy afterwards, and whether the distance is an implicit "reuse the
/// last one".
struct Command {
    insert: u32,
    copy: u32,
    implicit_distance: bool,
    /// §7.2: the distance context, from the copy length.
    distance_context: u8,
}

impl<'a> State<'a> {
    /// §10, the decoding algorithm, top to bottom.
    fn run(&mut self) -> Result<()> {
        let wbits = self.read_window_bits()?;
        #[cfg(test)]
        coverage::bump(&coverage::WINDOWS[wbits as usize]);
        self.window = (1 << wbits) - 16;
        loop {
            let islast = self.bits.bit()? != 0;
            if islast && self.bits.bit()? != 0 {
                // ISLASTEMPTY: the stream ends at this bit.
                break;
            }
            let mnibbles = self.read_mnibbles()?;
            if mnibbles == 0 {
                self.skip_metadata()?;
                if islast {
                    break;
                }
                continue;
            }
            let mlen = self.read_mlen(mnibbles)?;
            if !islast && self.bits.bit()? != 0 {
                // ISUNCOMPRESSED: a byte-aligned run of literals.
                self.read_stored(mlen)?;
                continue;
            }
            self.read_metablock(mlen)?;
            if islast {
                break;
            }
        }
        Ok(())
    }

    /// §9.1. A single 0 bit is 16; otherwise three bits give 18..24, and
    /// a further zero selects the 10..15 or 17 case. The seven-bit pattern
    /// that would give 12 a second spelling is reserved.
    fn read_window_bits(&mut self) -> Result<u32> {
        if self.bits.bit()? == 0 {
            return Ok(16);
        }
        let n = self.bits.take(3)?;
        if n != 0 {
            return Ok(17 + n);
        }
        let n = self.bits.take(3)?;
        Ok(match n {
            0 => 17,
            1 => return Err(Error::Reserved),
            _ => 8 + n,
        })
    }

    /// §9.2: a fixed two-bit code for 0, 4, 5 or 6 nibbles.
    fn read_mnibbles(&mut self) -> Result<u32> {
        Ok(match self.bits.take(2)? {
            3 => 0,
            0 => 4,
            1 => 5,
            _ => 6,
        })
    }

    /// §9.2: the meta-block length, minus one, in whole nibbles.
    fn read_mlen(&mut self, mnibbles: u32) -> Result<u32> {
        let nbits = mnibbles * 4;
        let raw = self.bits.take(nbits)?;
        // "If MNIBBLES is greater than 4, and the last nibble is all
        // zeros, then the stream should be rejected as invalid": the
        // length would have fit in fewer nibbles than the header spent.
        if mnibbles > 4 && (raw >> (nbits - 4)) == 0 {
            return Err(Error::Reserved);
        }
        Ok(raw + 1)
    }

    /// §9.2: a metadata meta-block carries bytes that are neither output
    /// nor window, so all the decoder does with one is step over it.
    fn skip_metadata(&mut self) -> Result<()> {
        if self.bits.bit()? != 0 {
            return Err(Error::Reserved);
        }
        let skip_bytes = self.bits.take(2)?;
        let len = if skip_bytes == 0 {
            0
        } else {
            let nbits = skip_bytes * 8;
            let raw = self.bits.take(nbits)?;
            // The same over-wide-header rule as MLEN.
            if skip_bytes > 1 && (raw >> (nbits - 8)) == 0 {
                return Err(Error::Reserved);
            }
            raw as usize + 1
        };
        #[cfg(test)]
        coverage::bump(&coverage::METADATA);
        self.bits.align()?;
        self.bits.skip_bytes(len).map(|_| ())
    }

    /// §9.2: an uncompressed meta-block is a byte-aligned run of literals,
    /// which still lands in the window and still sets the literal context.
    fn read_stored(&mut self, mlen: u32) -> Result<()> {
        #[cfg(test)]
        coverage::bump(&coverage::STORED);
        self.bits.align()?;
        let n = mlen as usize;
        let bytes = self.bits.take_bytes(n)?;
        if !self.cap.take(n as u64) {
            return Err(Error::Budget);
        }
        self.out.extend_from_slice(bytes);
        self.note(n);
        Ok(())
    }

    /// §9.2 and §10: one compressed meta-block, header and commands.
    fn read_metablock(&mut self, mlen: u32) -> Result<()> {
        let mut lit = self.read_blocks()?;
        let mut cmd = self.read_blocks()?;
        let mut dist = self.read_blocks()?;

        let npostfix = self.bits.take(2)?;
        let postfix_mask = (1u32 << npostfix) - 1;
        let ndirect = self.bits.take(4)? << npostfix;
        let dist_alphabet = 16 + ndirect as usize + (48usize << npostfix);

        let mut cmode = vec![0u8; lit.nbltypes];
        for slot in cmode.iter_mut() {
            *slot = self.bits.take(2)? as u8;
        }
        let ntrees_l = self.read_varlen()?;
        let cmap_l = self.read_context_map(ntrees_l, 64 * lit.nbltypes)?;
        let ntrees_d = self.read_varlen()?;
        let cmap_d = self.read_context_map(ntrees_d, 4 * dist.nbltypes)?;

        let mut htree_l = Vec::with_capacity(ntrees_l);
        for _ in 0..ntrees_l {
            htree_l.push(PrefixCode::read(&mut self.bits, 256)?);
        }
        let mut htree_i = Vec::with_capacity(cmd.nbltypes);
        for _ in 0..cmd.nbltypes {
            htree_i.push(PrefixCode::read(&mut self.bits, 704)?);
        }
        let mut htree_d = Vec::with_capacity(ntrees_d);
        for _ in 0..ntrees_d {
            htree_d.push(PrefixCode::read(&mut self.bits, dist_alphabet)?);
        }

        #[cfg(test)]
        coverage::bump(&coverage::METABLOCKS);
        let mut remaining = mlen;
        while remaining > 0 {
            if cmd.blen == 0 {
                cmd.switch(&mut self.bits)?;
            }
            cmd.blen -= 1;
            let sym = htree_i[cmd.btype].decode(&mut self.bits)?;
            let c = read_command(sym, &mut self.bits)?;

            for _ in 0..c.insert {
                if remaining == 0 {
                    return Err(Error::Overflow);
                }
                if lit.blen == 0 {
                    lit.switch(&mut self.bits)?;
                }
                lit.blen -= 1;
                #[cfg(test)]
                coverage::bump(&coverage::CONTEXT_MODES[(cmode[lit.btype] & 3) as usize]);
                let cid = literal_context(cmode[lit.btype], self.p1, self.p2) as usize;
                let tree = cmap_l[64 * lit.btype + cid];
                let b = htree_l
                    .get(tree as usize)
                    .ok_or(Error::Range)?
                    .decode(&mut self.bits)?;
                self.emit(b as u8)?;
                remaining -= 1;
            }
            // §9.3: a command whose insert part fills the meta-block ends
            // it there, and its copy length is ignored -- it can hold any
            // value at all.
            if remaining == 0 {
                break;
            }

            let distance = if c.implicit_distance {
                self.ring(0)
            } else {
                if dist.blen == 0 {
                    dist.switch(&mut self.bits)?;
                }
                dist.blen -= 1;
                let tree = cmap_d[4 * dist.btype + c.distance_context as usize];
                let dcode = htree_d
                    .get(tree as usize)
                    .ok_or(Error::Range)?
                    .decode(&mut self.bits)? as u32;
                if dcode >= dist_alphabet as u32 {
                    return Err(Error::Range);
                }
                let d = self.read_distance(dcode, npostfix, postfix_mask, ndirect)?;
                if d > MAX_DISTANCE {
                    return Err(Error::Range);
                }
                // A static dictionary word is not a past distance, so it
                // does not join the ring (§4). Neither does an EXPLICIT
                // distance code 0: §4's table names it "the last distance",
                // and reusing it must leave the ring where it was. Pushing
                // it duplicated the value into two adjacent slots, and a
                // later short code that counts slots back -- 2, the third
                // most recent -- resolved to the duplicate instead of the
                // distance it meant, which surfaced as five wrong bytes at
                // the end of a real quality-5 stream from the reference
                // encoder (and as truncations at quality 4 and 11).
                if dcode != 0 && d <= self.max_distance() {
                    self.push_distance(d);
                }
                d
            };

            if distance <= self.max_distance() {
                if c.copy > remaining {
                    return Err(Error::Overflow);
                }
                self.copy_back(distance, c.copy)?;
                remaining -= c.copy;
            } else {
                let produced = self.emit_word(distance, c.copy as usize)?;
                remaining = remaining.checked_sub(produced).ok_or(Error::Overflow)?;
            }
        }
        Ok(())
    }

    /// §9.2: one block category's header -- the number of block types,
    /// its two prefix codes, and the first block count.
    fn read_blocks(&mut self) -> Result<Blocks> {
        let nbltypes = self.read_varlen()?;
        if nbltypes < 2 {
            return Ok(Blocks {
                nbltypes,
                btype: 0,
                blen: 1 << 24,
                prev: 1,
                btype_code: PrefixCode::invalid(),
                blen_code: PrefixCode::invalid(),
            });
        }
        let btype_code = PrefixCode::read(&mut self.bits, nbltypes + 2)?;
        let blen_code = PrefixCode::read(&mut self.bits, 26)?;
        let blen = read_blen(&blen_code, &mut self.bits)?;
        Ok(Blocks {
            nbltypes,
            btype: 0,
            blen,
            prev: 1,
            btype_code,
            blen_code,
        })
    }

    /// §9.2's 1..11 bit code, for NBLTYPES and NTREES alike. A single 0
    /// bit is 1; a three-bit value of 0 is 2; otherwise `1 << n`, plus
    /// one, plus `n` more bits -- which tops out at 256.
    fn read_varlen(&mut self) -> Result<usize> {
        if self.bits.bit()? == 0 {
            return Ok(1);
        }
        let n = self.bits.take(3)?;
        if n == 0 {
            return Ok(2);
        }
        Ok(((1 << n) + 1 + self.bits.take(n)?) as usize)
    }

    /// §7.3: run-length coded values, optionally inverse-move-to-front
    /// transformed into prefix code indexes.
    fn read_context_map(&mut self, ntrees: usize, size: usize) -> Result<Vec<u8>> {
        if ntrees < 2 {
            return Ok(vec![0u8; size]);
        }
        // "RLEMAX, 0 is encoded with one 0 bit, and values 1..16 are
        // encoded with bit pattern xxxx1".
        let rlemax = if self.bits.bit()? == 0 {
            0
        } else {
            self.bits.take(4)? + 1
        };
        let code = PrefixCode::read(&mut self.bits, ntrees + rlemax as usize)?;
        let mut map = vec![0u8; size];
        let mut at = 0usize;
        while at < size {
            let sym = code.decode(&mut self.bits)? as u32;
            match sym {
                0 => {
                    map[at] = 0;
                    at += 1;
                }
                // Symbol s repeats a zero (1 << s) to (1 << (s+1)) - 1
                // times, with s extra bits.
                s if s <= rlemax => {
                    #[cfg(test)]
                    coverage::bump(&coverage::RLE_ZERO);
                    let reps = (1usize << s) + self.bits.take(s)? as usize;
                    if at + reps > size {
                        return Err(Error::Range);
                    }
                    at += reps;
                }
                s => {
                    map[at] = (s - rlemax) as u8;
                    at += 1;
                }
            }
        }
        #[cfg(test)]
        coverage::bump(&coverage::CONTEXT_MAPS);
        if self.bits.bit()? != 0 {
            #[cfg(test)]
            coverage::bump(&coverage::IMULTIPLE);
            inverse_move_to_front(&mut map);
        }
        Ok(map)
    }

    /// §4. Distance symbols 0..15 name a past distance; symbol 0, "the
    /// last distance", is the one that does not push onto the ring.
    fn read_distance(
        &mut self,
        dcode: u32,
        npostfix: u32,
        postfix_mask: u32,
        ndirect: u32,
    ) -> Result<u64> {
        if dcode < 16 {
            // (how far back in the ring, delta): 0 is the last distance,
            // 1 the second to last, and so on.
            const BACK: [(u32, i32); 16] = [
                (0, 0),
                (1, 0),
                (2, 0),
                (3, 0),
                (0, -1),
                (0, 1),
                (0, -2),
                (0, 2),
                (0, -3),
                (0, 3),
                (1, -1),
                (1, 1),
                (1, -2),
                (1, 2),
                (1, -3),
                (1, 3),
            ];
            #[cfg(test)]
            coverage::bump(&coverage::SHORT_DIST[dcode as usize]);
            let (back, delta) = BACK[dcode as usize];
            let d = self.ring(back) as i64 + delta as i64;
            if d <= 0 {
                return Err(Error::Range);
            }
            return Ok(d as u64);
        }
        // The NDIRECT symbols from 16 name distances 1..NDIRECT with no
        // extra bits.
        if dcode < 16 + ndirect {
            #[cfg(test)]
            coverage::bump(&coverage::DIRECT_DIST);
            return Ok((dcode - 15) as u64);
        }
        #[cfg(test)]
        coverage::bump(&coverage::COMPUTED_DIST);
        let d = dcode - ndirect - 16;
        let ndistbits = 1 + (d >> (npostfix + 1));
        let dextra = self.bits.take(ndistbits)? as u64;
        let hcode = d >> npostfix;
        let offset = ((2 + (hcode & 1)) << ndistbits) - 4;
        let distance =
            ((offset as u64 + dextra) << npostfix) + (d & postfix_mask) as u64 + ndirect as u64 + 1;
        Ok(distance)
    }

    /// The `back`-th most recent distance, 0 being the last.
    fn ring(&self, back: u32) -> u64 {
        self.dist_rb[(self.dist_rb_idx + 3 - back as usize) & 3] as u64
    }

    fn push_distance(&mut self, d: u64) {
        self.dist_rb[self.dist_rb_idx & 3] = d as u32;
        self.dist_rb_idx += 1;
    }

    /// §8: the largest backward distance that still means "already
    /// produced", which is the smaller of the window and the output.
    fn max_distance(&self) -> u64 {
        (self.window as u64).min(self.out.len() as u64)
    }

    /// §8: a distance past everything produced names a static dictionary
    /// word and one of the 121 transformations of it. Applied and emitted
    /// in one step, because a transform can change the word's length.
    ///
    /// **A copy longer than the longest word is two copies, and refusing it
    /// rejected every reference stream the reference encoder emits this
    /// way.** The word comes from the 24 bucket -- there is no longer one
    /// -- and the rest of the copy is a backward reference over what the
    /// word just produced, at the distance of the word's own TRANSFORMED
    /// length, so a copy of any length repeats the word for as long as it
    /// runs. The whole copy is `len` bytes either way, which is what the
    /// meta-block's remaining count is debited. Found by the reference
    /// encoder at quality 5 on a 1,381-byte Rust source: every stream it
    /// produced that used the shape was rejected with `Range`, and the
    /// oracle vectors were all small enough never to take it.
    fn emit_word(&mut self, distance: u64, len: usize) -> Result<u32> {
        let word_len = len.min(MAX_WORD);
        if word_len < MIN_WORD {
            return Err(Error::Range);
        }
        let word_id = distance - self.max_distance() - 1;
        let shift = tables::DICT_SIZE_BITS[word_len];
        let index = (word_id & ((1u64 << shift) - 1)) as usize;
        let transform_id = word_id >> shift;
        let transform = *tables::TRANSFORMS
            .get(transform_id as usize)
            .ok_or(Error::Range)?;
        let offset = tables::DICT_OFFSET[word_len] as usize + index * word_len;
        #[cfg(test)]
        {
            coverage::bump(&coverage::DICT_WORDS);
            coverage::bump(&coverage::TRANSFORMS[transform_id as usize]);
        }
        let mut buf = [0u8; TRANSFORM_BUFFER];
        let n = apply_transform(
            &mut buf,
            &tables::DICT[offset..offset + word_len],
            &transform,
        );
        if !self.cap.take(n as u64) {
            return Err(Error::Budget);
        }
        self.out.extend_from_slice(&buf[..n]);
        self.note(n);
        if len > MAX_WORD {
            // The word's transformed length is the distance the remainder
            // copies at; `copy_back` handles the overlap, which is the
            // repetition. The whole copy is `len` bytes.
            self.copy_back(n as u64, (len - n) as u32)?;
            Ok(len as u32)
        } else {
            // A short copy is debited by the TRANSFORMED length, which a
            // suffix or an omission can push either side of `len`.
            Ok(n as u32)
        }
    }

    /// Copy `len` bytes from `distance` back. One byte at a time, because
    /// the source and the destination overlap whenever the distance is
    /// shorter than the length, which is legal and common (§10).
    fn copy_back(&mut self, distance: u64, len: u32) -> Result<()> {
        let from = self
            .out
            .len()
            .checked_sub(distance as usize)
            .ok_or(Error::Range)?;
        if !self.cap.take(len as u64) {
            return Err(Error::Budget);
        }
        self.out.reserve(len as usize);
        for i in 0..len as usize {
            let b = self.out[from + i];
            self.out.push(b);
        }
        self.note(len as usize);
        Ok(())
    }

    fn emit(&mut self, b: u8) -> Result<()> {
        if !self.cap.take(1) {
            return Err(Error::Budget);
        }
        self.out.push(b);
        self.note(1);
        Ok(())
    }

    /// Keep the two-byte literal context up to date with what was just
    /// produced, whichever way it was produced (§7.1).
    fn note(&mut self, n: usize) {
        match n {
            0 => {}
            1 => {
                self.p2 = self.p1;
                self.p1 = self.out[self.out.len() - 1];
            }
            _ => {
                self.p1 = self.out[self.out.len() - 1];
                self.p2 = self.out[self.out.len() - 2];
            }
        }
    }
}

/// §5: split the insert-and-copy length code into its two halves and read
/// their extra bits.
fn read_command(sym: u16, bits: &mut Bits) -> Result<Command> {
    if sym >= 704 {
        return Err(Error::Symbol);
    }
    let cell = (sym >> 6) as usize;
    let (ibase, cbase) = SPLIT[cell];
    let ins_code = ibase as usize + ((sym >> 3) & 7) as usize;
    let copy_code = cbase as usize + (sym & 7) as usize;
    Ok(Command {
        insert: INSERT_BASE[ins_code] + bits.take(INSERT_EXTRA[ins_code])?,
        copy: COPY_BASE[copy_code] + bits.take(COPY_EXTRA[copy_code])?,
        // §5: the first 128 symbols are the ones that say so.
        implicit_distance: cell < 2,
        // §7.2: the context of a copy length 2, 3, 4, or longer.
        distance_context: COPY_BASE[copy_code].saturating_sub(2).min(3) as u8,
    })
}

/// §7.3's inverse move-to-front transform.
fn inverse_move_to_front(v: &mut [u8]) {
    let mut mtf = [0u8; 256];
    for (i, slot) in mtf.iter_mut().enumerate() {
        *slot = i as u8;
    }
    for slot in v.iter_mut() {
        let index = *slot as usize;
        let value = mtf[index];
        *slot = value;
        mtf.copy_within(0..index, 1);
        mtf[0] = value;
    }
}

/// §8: `transform(word) = prefix + T(word) + suffix`, written into `dst`.
/// Returns how many bytes that came to.
fn apply_transform(
    dst: &mut [u8; TRANSFORM_BUFFER],
    word: &[u8],
    transform: &tables::Transform,
) -> usize {
    let mut n = 0;
    for &b in transform.prefix {
        dst[n] = b;
        n += 1;
    }
    // How much of the word the elementary transform keeps, and from where.
    // OmitFirst8 is in the alphabet but no transform uses it.
    let kind = transform.kind as u8;
    let (skip, keep) = if (Kind::OmitFirst1 as u8..=Kind::OmitFirst9 as u8).contains(&kind) {
        let k = (kind - Kind::OmitFirst1 as u8 + 1) as usize;
        (k.min(word.len()), word.len() - k.min(word.len()))
    } else if (Kind::OmitLast1 as u8..=Kind::OmitLast9 as u8).contains(&kind) {
        let k = (kind - Kind::OmitLast1 as u8 + 1) as usize;
        (0, word.len().saturating_sub(k))
    } else {
        (0, word.len())
    };
    let at = n;
    dst[n..n + keep].copy_from_slice(&word[skip..skip + keep]);
    n += keep;
    match transform.kind {
        Kind::FermentFirst if keep > 0 => {
            ferment(&mut dst[at..n], 0);
        }
        Kind::FermentAll => {
            let mut i = 0;
            while i < keep {
                i += ferment(&mut dst[at..n], i);
            }
        }
        _ => {}
    }
    for &b in transform.suffix {
        dst[n] = b;
        n += 1;
    }
    n
}

/// §8's `Ferment`: case-folds one character the way the specification
/// defines it, and says how wide that character was so a caller can walk
/// a run of them.
fn ferment(word: &mut [u8], at: usize) -> usize {
    if word[at] < 192 {
        if word[at].is_ascii_lowercase() {
            word[at] ^= 32;
        }
        1
    } else if word[at] < 224 {
        if at + 1 < word.len() {
            word[at + 1] ^= 32;
        }
        2
    } else {
        if at + 2 < word.len() {
            word[at + 2] ^= 5;
        }
        3
    }
}
