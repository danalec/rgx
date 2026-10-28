// SPDX-License-Identifier: Apache-2.0

//! LZMA1 and the LZMA2 chunk layer: range coding over a Markov
//! probability model, the literal/match/repeat state machine, and the
//! dictionary those symbols draw on.
//!
//! Independent reimplementation of the published LZMA specification
//! (range coder, 11-bit probability model, the literal/match state
//! machine and its length/distance codes) plus the LZMA2 chunk framing
//! xz and 7z use, written from those format descriptions rather than
//! from any implementation's source. Decoding only — rgx reads LZMA for
//! zip method 14 and the xz container and produces neither. Validated
//! against liblzma-generated vectors in `testdata/lzma_*.bin`.
//!
//! Two contracts the containers depend on: FORMAT_ALONE's header declares
//! the uncompressed size in bytes 5..13, so a stream that declares more
//! than the ceiling is refused before decoding anything; and a match is
//! never allowed to cross the target a chunk is aiming at, which is what
//! makes a truncated or over-declared chunk an error instead of a silent
//! overshoot.

use crate::compress::cap::Bounded;
use crate::compress::error::{CompressError, CompressResult};
use alloc::vec;
use alloc::vec::Vec;

/// LZMA properties
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaProps {
    pub lc: u8,
    pub lp: u8,
    pub pb: u8,
}

impl Default for LzmaProps {
    fn default() -> Self {
        Self {
            lc: 3,
            lp: 0,
            pb: 2,
        }
    }
}

impl LzmaProps {
    /// Decode the one-byte properties field: `(pb * 5 + lp) * 9 + lc`.
    pub fn from_byte(byte: u8) -> Result<Self, CompressError> {
        if byte >= 225 {
            return Err(CompressError::InvalidFormat("invalid LZMA properties"));
        }
        let lc = byte % 9;
        let rest = byte / 9;
        let lp = rest % 5;
        let pb = rest / 5;
        Ok(Self { lc, lp, pb })
    }

    pub fn to_byte(self) -> u8 {
        (self.pb * 5 + self.lp) * 9 + self.lc
    }
}

/// Smallest dictionary the format allows (4 KiB).
pub const LZMA_DICT_MIN: u32 = 1 << 12;
/// Largest dictionary the format allows (128 MiB).
pub const LZMA_DICT_MAX: u32 = 1 << 27;

/// Compression level knob for producers. Carried for API stability; this
/// crate decodes LZMA and does not produce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LzmaLevel(pub u8);

impl LzmaLevel {
    pub const FASTEST: Self = Self(0);
    pub const FAST: Self = Self(1);
    pub const NORMAL: Self = Self(3);
    pub const MAX: Self = Self(6);
    pub const ULTRA: Self = Self(9);
}

/// Model constants from the specification.
const PROB_TOTAL: u16 = 2048; // 2^11: the model's full scale
const PROB_INIT: u16 = PROB_TOTAL / 2; // an even coin for a new bit
const NUM_STATES: usize = 12;
const NUM_POS_BITS_MAX: usize = 4;
const NUM_LEN_TO_POS_STATES: usize = 4;
const NUM_POS_SLOTS: usize = 64; // 6-bit tree
const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX >> 1); // 128
/// SpecPos: the reverse bit-trees for distance slots 4..13, indexed by
/// (distance_base - slot). Size 115 covers the last slot's walk, which
/// reads 32 entries from offset 83.
const NUM_POS_SPECIAL: usize = NUM_FULL_DISTANCES - END_POS_MODEL_INDEX + 1; // 115
const END_POS_MODEL_INDEX: usize = 14;
const ALIGN_BITS: u32 = 4;
const ALIGN_TABLE_SIZE: usize = 1 << ALIGN_BITS;
const MATCH_MIN_LEN: usize = 2;
const LEN_LOW_BITS: u32 = 3;
const LEN_MID_BITS: u32 = 3;
const LEN_HIGH_BITS: u32 = 8;
const LEN_LOW_SIZE: usize = 1 << LEN_LOW_BITS;
const LEN_MID_SIZE: usize = 1 << LEN_MID_BITS;
const LEN_HIGH_SIZE: usize = 1 << LEN_HIGH_BITS;

/// The range coder's state: a 32-bit window over the code and the range
/// it is decoding within. Bits come out one at a time against 11-bit
/// probabilities.
struct RangeReader<'a> {
    input: &'a [u8],
    pos: usize,
    code: u32,
    range: u32,
}

impl<'a> RangeReader<'a> {
    fn new(input: &'a [u8]) -> CompressResult<Self> {
        if input.is_empty() {
            return Err(CompressError::UnexpectedEof);
        }
        // First byte is a required zero marker; the next five fill `code`.
        if input[0] != 0 {
            return Err(CompressError::InvalidFormat("bad LZMA range coder init"));
        }
        let mut code = 0u32;
        for i in 1..5 {
            code = (code << 8) | *input.get(i).ok_or(CompressError::UnexpectedEof)? as u32;
        }
        Ok(Self {
            input,
            pos: 5,
            code,
            range: 0xFFFF_FFFF,
        })
    }

    fn next_byte(&mut self) -> CompressResult<u32> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(CompressError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b as u32)
    }

    /// Keep `range` in its top byte by pulling in a fresh one.
    fn normalize(&mut self) -> CompressResult<()> {
        if self.range < 1 << 24 {
            self.range <<= 8;
            self.code = (self.code << 8) | self.next_byte()?;
        }
        Ok(())
    }

    /// Decode one bit against `prob`, updating it toward the bit seen.
    fn bit(&mut self, prob: &mut u16) -> CompressResult<u32> {
        let bound = (self.range >> 11) * (*prob as u32);
        let bit = if self.code < bound {
            self.range = bound;
            *prob += (PROB_TOTAL - *prob) >> 5;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= *prob >> 5;
            1
        };
        self.normalize()?;
        Ok(bit)
    }

    /// A fixed-width field of direct bits, most significant first.
    fn direct(&mut self, bits: u32) -> CompressResult<u32> {
        let mut value = 0u32;
        for _ in 0..bits {
            self.range >>= 1;
            let bit = u32::from(self.code >= self.range);
            self.code -= self.range & (0u32.wrapping_sub(bit));
            value = (value << 1) | bit;
            self.normalize()?;
        }
        Ok(value)
    }

    /// Bit-tree code read most-significant bit first.
    fn tree(&mut self, probs: &mut [u16], bits: u32) -> CompressResult<u32> {
        let mut index = 1usize;
        for _ in 0..bits {
            let b = self.bit(&mut probs[index])? as usize;
            index = (index << 1) | b;
        }
        Ok((index - (1usize << bits)) as u32)
    }

    /// Bit-tree code read least-significant bit first (the distance
    /// align tree and the tail of wide distances).
    fn tree_reverse(&mut self, probs: &mut [u16], bits: u32) -> CompressResult<u32> {
        let mut index = 1usize;
        let mut value = 0u32;
        for i in 0..bits {
            let b = self.bit(&mut probs[index])? as usize;
            index = (index << 1) | b;
            value |= (b as u32) << i;
        }
        Ok(value)
    }
}

/// Match-length coder: two single-bit switches pick low/mid/high trees.
struct LengthCoder {
    choice: u16,
    choice2: u16,
    low: [[u16; LEN_LOW_SIZE]; 1 << NUM_POS_BITS_MAX],
    mid: [[u16; LEN_MID_SIZE]; 1 << NUM_POS_BITS_MAX],
    high: [u16; LEN_HIGH_SIZE],
}

impl LengthCoder {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; LEN_LOW_SIZE]; 1 << NUM_POS_BITS_MAX],
            mid: [[PROB_INIT; LEN_MID_SIZE]; 1 << NUM_POS_BITS_MAX],
            high: [PROB_INIT; LEN_HIGH_SIZE],
        }
    }

    /// A match length in `0..=271`; the caller adds the minimum length.
    fn decode(&mut self, rc: &mut RangeReader, pos_state: usize) -> CompressResult<usize> {
        if rc.bit(&mut self.choice)? == 0 {
            Ok(rc.tree(&mut self.low[pos_state], LEN_LOW_BITS)? as usize)
        } else if rc.bit(&mut self.choice2)? == 0 {
            Ok(8 + rc.tree(&mut self.mid[pos_state], LEN_MID_BITS)? as usize)
        } else {
            Ok(16 + rc.tree(&mut self.high, LEN_HIGH_BITS)? as usize)
        }
    }
}

/// The four most-recent match distances and the 12-state machine.
struct Machine {
    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
}

impl Machine {
    fn new() -> Self {
        Self {
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
        }
    }

    fn after_literal(&mut self) {
        self.state = if self.state < 4 {
            0
        } else if self.state < 10 {
            self.state - 3
        } else {
            self.state - 6
        };
    }

    fn after_match(&mut self) {
        self.state = if self.state < 7 { 7 } else { 10 };
    }

    fn after_rep(&mut self) {
        self.state = if self.state < 7 { 8 } else { 11 };
    }

    fn after_short_rep(&mut self) {
        self.state = if self.state < 7 { 9 } else { 11 };
    }

    /// True when the previous symbol was a literal (the matched-literal
    /// path is only for states where a match just preceded).
    fn after_literal_context(&self) -> bool {
        self.state < 7
    }

    fn push_rep(&mut self, dist: u32) {
        self.rep3 = self.rep2;
        self.rep2 = self.rep1;
        self.rep1 = self.rep0;
        self.rep0 = dist;
    }
}

/// The full probability model and the symbol loop.
struct LzmaEngine {
    machine: Machine,
    is_match: [[u16; 1 << NUM_POS_BITS_MAX]; NUM_STATES],
    is_rep: [u16; NUM_STATES],
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [[u16; 1 << NUM_POS_BITS_MAX]; NUM_STATES],
    match_len: LengthCoder,
    rep_len: LengthCoder,
    literal: Vec<[u16; 0x300]>,
    pos_slot: [[u16; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES],
    pos_special: [u16; NUM_POS_SPECIAL],
    align: [u16; ALIGN_TABLE_SIZE],
}

impl LzmaEngine {
    /// Build the probability model for `props`.
    ///
    /// The literal table is one row of `0x300` probabilities per literal
    /// context, and there are `1 << (lc + lp)` contexts. The row count was
    /// `0x300 << (lc + lp)`, which made the table 768 times the model: the
    /// default properties asked for 9 MiB where the model is 12 KiB, and a
    /// properties byte of 44 -- `lc = 8`, `lp = 4` -- asked for 4.5 GiB out
    /// of twenty-one bytes of input.
    ///
    /// The specification bounds `lc` at 8, `lp` at 4 and `pb` at 4, and
    /// properties outside that cannot be modelled: the table would not fit
    /// and the position model would be indexed out of bounds. A properties
    /// byte from a file always lands in range (`from_byte` cannot produce
    /// another), so this refuses the hand-made ones.
    fn new(props: LzmaProps) -> CompressResult<Self> {
        if props.lc > 8 || props.lp > 4 || props.pb > 4 {
            return Err(CompressError::InvalidFormat("LZMA properties out of range"));
        }
        let lit_len = 1usize << (props.lc + props.lp);
        Ok(Self {
            machine: Machine::new(),
            is_match: [[PROB_INIT; 1 << NUM_POS_BITS_MAX]; NUM_STATES],
            is_rep: [PROB_INIT; NUM_STATES],
            is_rep_g0: [PROB_INIT; NUM_STATES],
            is_rep_g1: [PROB_INIT; NUM_STATES],
            is_rep_g2: [PROB_INIT; NUM_STATES],
            is_rep0_long: [[PROB_INIT; 1 << NUM_POS_BITS_MAX]; NUM_STATES],
            match_len: LengthCoder::new(),
            rep_len: LengthCoder::new(),
            literal: vec![[PROB_INIT; 0x300]; lit_len],
            pos_slot: [[PROB_INIT; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES],
            pos_special: [PROB_INIT; NUM_POS_SPECIAL],
            align: [PROB_INIT; ALIGN_TABLE_SIZE],
        })
    }

    fn reset_state(&mut self) {
        // Sizes come from the properties the engine was built with; a
        // state reset refills probabilities, it does not resize the model.
        self.machine = Machine::new();
        for row in self.is_match.iter_mut() {
            row.fill(PROB_INIT);
        }
        self.is_rep.fill(PROB_INIT);
        self.is_rep_g0.fill(PROB_INIT);
        self.is_rep_g1.fill(PROB_INIT);
        self.is_rep_g2.fill(PROB_INIT);
        for row in self.is_rep0_long.iter_mut() {
            row.fill(PROB_INIT);
        }
        self.match_len = LengthCoder::new();
        self.rep_len = LengthCoder::new();
        for entry in self.literal.iter_mut() {
            entry.fill(PROB_INIT);
        }
        for row in self.pos_slot.iter_mut() {
            row.fill(PROB_INIT);
        }
        self.pos_special.fill(PROB_INIT);
        self.align.fill(PROB_INIT);
    }

    fn pos_mask(props: &LzmaProps) -> usize {
        (1 << props.pb) - 1
    }

    /// Which literal probability set a byte at `pos_abs` uses: the
    /// low `lp` bits of the position (relative to the dictionary start)
    /// and the top `lc` bits of the previous byte.
    fn lit_state(props: &LzmaProps, out: &[u8], pos_abs: usize, dict_base: usize) -> usize {
        let lc = props.lc as usize;
        let lp = props.lp as usize;
        let pos_rel = pos_abs.saturating_sub(dict_base);
        ((pos_rel & ((1 << lp) - 1)) << lc)
            + (if pos_abs > dict_base {
                out[pos_abs - 1] as usize >> (8 - lc)
            } else {
                0
            })
    }

    /// Decode symbols until `unpack` bytes are produced.
    /// `dict_base` is the index in `out` where the current dictionary
    /// window starts (LZMA2 dictionary resets).
    ///
    /// Returns `true` if the end-of-stream marker was hit.
    /// Decode one chunk. `unpack` is the target the caller is aiming at and
    /// `hard_cap` a second, lower ceiling that is a stopping point rather
    /// than an error: a match that would cross it ends the chunk cleanly, so
    /// a bomb stops where the cap is instead of failing as corrupt.
    fn decode_chunk(
        &mut self,
        rc: &mut RangeReader,
        props: &LzmaProps,
        out: &mut Vec<u8>,
        unpack: usize,
        dict_base: usize,
        hard_cap: usize,
    ) -> CompressResult<bool> {
        let pos_mask = Self::pos_mask(props);

        let target = out.len().saturating_add(unpack).min(hard_cap);
        while out.len() < target {
            // LZMA2's position counter resets with the dictionary, so the
            // state index is the offset since `dict_base`, not the absolute
            // output length.
            let pos_state = (out.len() - dict_base) & pos_mask;

            if rc.bit(&mut self.is_match[self.machine.state][pos_state])? == 0 {
                // Literal
                let probs = &mut self.literal[Self::lit_state(props, out, out.len(), dict_base)];
                let mut symbol = 1usize;
                if self.machine.after_literal_context() {
                    while symbol < 0x100 {
                        let b = rc.bit(&mut probs[symbol])? as usize;
                        symbol = (symbol << 1) | b;
                    }
                } else {
                    let dist = self.machine.rep0 as usize;
                    let mb_pos =
                        out.len()
                            .checked_sub(dist + 1)
                            .ok_or(CompressError::InvalidFormat(
                                "LZMA rep distance out of range",
                            ))?;
                    if mb_pos < dict_base {
                        return Err(CompressError::InvalidFormat(
                            "LZMA rep distance before dictionary start",
                        ));
                    }
                    let mut match_byte = out[mb_pos] as usize;
                    let mut offset: usize = 0x100;
                    while symbol < 0x100 {
                        match_byte <<= 1;
                        let match_bit = match_byte & offset;
                        let b = rc.bit(&mut probs[offset + match_bit + symbol])? as usize;
                        symbol = (symbol << 1) | b;
                        offset &= !(match_bit ^ (b * 0x100));
                    }
                }
                out.push((symbol - 0x100) as u8);
                self.machine.after_literal();
                continue;
            }

            // Match or rep
            let len;
            if rc.bit(&mut self.is_rep[self.machine.state])? != 0 {
                // Rep match
                if rc.bit(&mut self.is_rep_g0[self.machine.state])? == 0 {
                    if rc.bit(&mut self.is_rep0_long[self.machine.state][pos_state])? == 0 {
                        // Short rep: copy 1 byte
                        self.machine.after_short_rep();
                        let dist = self.machine.rep0 as usize;
                        let src = out
                            .len()
                            .checked_sub(dist + 1)
                            .ok_or(CompressError::InvalidFormat("LZMA rep0 out of range"))?;
                        if src < dict_base {
                            return Err(CompressError::InvalidFormat(
                                "LZMA rep0 before dictionary start",
                            ));
                        }
                        let b = out[src];
                        out.push(b);
                        continue;
                    }
                } else {
                    let dist;
                    if rc.bit(&mut self.is_rep_g1[self.machine.state])? == 0 {
                        dist = self.machine.rep1;
                    } else if rc.bit(&mut self.is_rep_g2[self.machine.state])? == 0 {
                        dist = self.machine.rep2;
                        self.machine.rep2 = self.machine.rep1;
                    } else {
                        dist = self.machine.rep3;
                        self.machine.rep3 = self.machine.rep2;
                        self.machine.rep2 = self.machine.rep1;
                    }
                    self.machine.rep1 = self.machine.rep0;
                    self.machine.rep0 = dist;
                }
                len = self.rep_len.decode(rc, pos_state)? + MATCH_MIN_LEN;
                self.machine.after_rep();
            } else {
                // Simple match
                self.machine.push_rep(0);
                len = self.match_len.decode(rc, pos_state)? + MATCH_MIN_LEN;
                self.machine.after_match();

                let len_state = (len - MATCH_MIN_LEN).min(NUM_LEN_TO_POS_STATES - 1);
                let slot = rc.tree(&mut self.pos_slot[len_state][..], 6)? as usize;

                let mut dist;
                if slot < 4 {
                    dist = slot as u32;
                } else {
                    let num_direct = ((slot >> 1) - 1) as u32;
                    dist = (2 | (slot & 1) as u32) << num_direct;
                    if slot < END_POS_MODEL_INDEX {
                        let start = (dist - slot as u32) as usize;
                        dist += rc.tree_reverse(&mut self.pos_special[start..], num_direct)?;
                    } else {
                        dist += rc.direct(num_direct - ALIGN_BITS)? << ALIGN_BITS;
                        dist += rc.tree_reverse(&mut self.align[..], ALIGN_BITS)?;
                    }
                }

                if dist == u32::MAX {
                    // End-of-stream marker
                    return Ok(true);
                }
                self.machine.rep0 = dist;
            }

            // Copy match. LZMA distances are zero-based: the source is
            // `dist + 1` bytes back.
            let dist = self.machine.rep0 as usize;
            if dist + 1 > out.len() - dict_base {
                return Err(CompressError::InvalidFormat(
                    "LZMA match distance out of range",
                ));
            }
            if out.len() + len > target {
                if target != hard_cap {
                    return Err(CompressError::InvalidFormat("LZMA chunk size mismatch"));
                }
                // The cap is what bounds this chunk, not the container.
                // Emit the part of the match that fits and stop: refusing
                // it whole would hand the caller a decode that had made no
                // progress at all, and LZMA1 has no chunk boundary to stop
                // at, so there would be nothing to stop on either.
                let room = target - out.len();
                let start = out.len() - dist - 1;
                for i in 0..room {
                    let b = out[start + i];
                    out.push(b);
                }
                return Ok(false);
            }
            let start = out.len() - dist - 1;
            for i in 0..len {
                let b = out[start + i];
                out.push(b);
            }
        }
        Ok(false)
    }
}

pub struct LzmaDecoder;

impl LzmaDecoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode a legacy `.lzma` (FORMAT_ALONE) stream: 1-byte props, 4-byte
    /// little-endian dictionary size, 8-byte little-endian uncompressed size
    /// (0xFFFF..FFFF = unknown).
    pub fn decode(&self, input: &[u8]) -> CompressResult<Vec<u8>> {
        self.decode_bounded(input, super::cap::UNLIMITED)
            .map(|b| b.bytes)
    }

    /// Decode a legacy `.lzma` stream without expanding it past `limit`
    /// bytes. FORMAT_ALONE's header carries the uncompressed size in bytes
    /// 5..13, so a stream that declares more than the limit is refused
    /// before a single byte is decoded. That field is all-ones when the
    /// encoder did not know the size, and then the ceiling has to be the
    /// running one.
    pub fn decode_bounded(&self, input: &[u8], limit: u64) -> CompressResult<Bounded> {
        if input.len() < 13 {
            return Err(CompressError::UnexpectedEof);
        }

        let props = LzmaProps::from_byte(input[0])?;
        let dict_size = u32::from_le_bytes([input[1], input[2], input[3], input[4]]);
        let size_raw = u64::from_le_bytes([
            input[5], input[6], input[7], input[8], input[9], input[10], input[11], input[12],
        ]);
        let unpack_size = if size_raw == u64::MAX {
            None
        } else {
            Some(size_raw)
        };

        // Empty payload is valid when the uncompressed size is zero.
        if unpack_size == Some(0) && input.len() == 13 {
            return Ok(Bounded::complete(Vec::new(), Some(0), limit));
        }
        if let Some(n) = unpack_size {
            if n > limit {
                return Ok(Bounded::stopped(Vec::new(), Some(n), limit));
            }
        }

        self.decode_raw_bounded(&input[13..], props, dict_size, unpack_size, limit)
    }

    /// Decode a raw LZMA1 stream (no header), as stored inside 7z archives.
    pub fn decode_raw(
        &self,
        input: &[u8],
        props: LzmaProps,
        dict_size: u32,
        unpack_size: Option<u64>,
    ) -> CompressResult<Vec<u8>> {
        self.decode_raw_bounded(input, props, dict_size, unpack_size, super::cap::UNLIMITED)
            .map(|b| b.bytes)
    }

    /// [`Self::decode_raw`] under a ceiling on the output.
    pub fn decode_raw_bounded(
        &self,
        input: &[u8],
        props: LzmaProps,
        dict_size: u32,
        unpack_size: Option<u64>,
        limit: u64,
    ) -> CompressResult<Bounded> {
        let mut rc = RangeReader::new(input)?;
        let mut core = LzmaEngine::new(props)?;
        let mut out: Vec<u8> = Vec::with_capacity(unpack_size.unwrap_or(0).min(1 << 26) as usize);
        let mut cap = super::cap::OutputCap::new(limit);
        let mut counted = 0u64;

        let unpack = match unpack_size {
            Some(n) => n as usize,
            None => usize::MAX,
        };
        loop {
            let remaining = unpack.saturating_sub(out.len());
            if remaining == 0 {
                break;
            }
            // A *minimum* per call, never a maximum: `decode_chunk`
            // refuses a match crossing its target, and LZMA1 has no
            // chunk structure, so capping the target made every match
            // straddling 16 MiB a hard error. See upstream 7db078d.
            // The target depends on whether the size is known, and
            // getting it wrong fails silently in both directions.
            //
            // Unknown size: the only terminator is the end-of-stream
            // marker, and there is nothing else to aim at. `decode_chunk`
            // refuses a match crossing its target and LZMA1 has no chunk
            // structure, so any finite target makes every match straddling
            // it a hard error. `remaining` is already usize::MAX here.
            //
            // Known size: the stream usually carries no end marker at all,
            // because the container already said how many bytes to expect.
            // Aiming past that overshoots the payload and runs off the end
            // of the input -- "unexpected end of input" on a file every
            // other tool reads. This is what 7-Zip emits for its LZMA1
            // coder, and the 16 MiB floor broke every such archive.
            let chunk = match unpack_size {
                Some(_) => remaining,
                None => usize::MAX,
            };
            let ended = core.decode_chunk(
                &mut rc,
                &props,
                &mut out,
                chunk,
                0,
                cap.remaining().min(usize::MAX as u64) as usize,
            )?;
            let emitted = out.len() as u64;
            if emitted > counted {
                cap.take(emitted - counted);
                counted = emitted;
            }
            if ended || out.len() >= unpack {
                break;
            }
            // `take` only refuses past the limit, so reaching it exactly is
            // the cap too: without this the chunk loop would spin on a
            // target it has already hit. Checked after the stream's own end
            // so a file that is exactly the cap long is not called short.
            if cap.capped() || emitted >= limit {
                return Ok(Bounded::stopped(out, unpack_size, limit));
            }
            if chunk == 0 {
                break;
            }
        }
        if let Some(n) = unpack_size {
            if out.len() != n as usize {
                return Err(CompressError::UnexpectedEof);
            }
        }
        let _ = dict_size;
        Ok(Bounded::complete(out, unpack_size, limit))
    }

    /// Decode a raw LZMA2 chunk stream (as used by xz and 7z).
    pub fn decode_lzma2(&self, input: &[u8], dict_size: u32) -> CompressResult<Vec<u8>> {
        self.decode_lzma2_bounded(input, dict_size, super::cap::UNLIMITED)
            .map(|b| b.bytes)
    }

    /// [`Self::decode_lzma2`] under a ceiling on the output. Every LZMA2
    /// chunk declares its own uncompressed size in the control byte and the
    /// two size fields, so the cap is checked against that declaration
    /// before the chunk is decoded, and again against what it produced.
    pub fn decode_lzma2_bounded(
        &self,
        mut input: &[u8],
        dict_size: u32,
        limit: u64,
    ) -> CompressResult<Bounded> {
        let mut out: Vec<u8> = Vec::new();
        let mut cap = super::cap::OutputCap::new(limit);
        let mut props: Option<LzmaProps> = None;
        let mut core: Option<LzmaEngine> = None;
        let mut need_dict_reset = true;
        // After an uncompressed chunk the LZMA state is invalid until a
        // chunk resets it (control >= 0xA0).
        let mut state_valid = false;
        // liblzma's `need_props` (lzma2_decoder.c): a dictionary reset
        // requires properties, and only a chunk that carries them clears
        // the requirement. A control byte >= 0xC0 does both at once, so
        // the only reset that leaves the flag standing is 0x01 (reset
        // with a single uncompressed byte and no properties). The next
        // LZMA chunk then has to set new properties, because the state
        // that goes with a new dictionary is the state that goes with new
        // properties. Without the check a 0xA0 chunk straight after a 0x01
        // reset is accepted here and rejected everywhere else.
        let mut need_props = false;
        let mut dict_base = 0usize;

        loop {
            let Some(&control) = input.first() else {
                return Err(CompressError::UnexpectedEof);
            };
            input = &input[1..];

            if control == 0x00 {
                break;
            }

            if control >= 0xE0 || control == 0x01 {
                // Dictionary reset
                need_dict_reset = false;
                need_props = true;
                dict_base = out.len();
            } else if need_dict_reset {
                return Err(CompressError::InvalidFormat(
                    "LZMA2 stream missing dictionary reset",
                ));
            }

            if control >= 0x80 {
                // LZMA chunk: [control][uncompressed size (5 bits in the
                // control byte + 2 BE bytes)][packed size u16 BE], then the
                // payload, then the new properties byte when control >= 0xC0.
                if input.len() < 4 {
                    return Err(CompressError::UnexpectedEof);
                }
                let unpack = ((((control & 0x1F) as usize) << 16)
                    | u16::from_be_bytes([input[0], input[1]]) as usize)
                    + 1;
                let packed = u16::from_be_bytes([input[2], input[3]]) as usize + 1;
                input = &input[4..];

                // The chunk states how many bytes it will produce, so a
                // chunk that cannot fit is refused from the statement
                // rather than decoded to find out.
                if !cap.fits(unpack as u64) {
                    return Ok(Bounded::stopped(out, None, limit));
                }

                if need_props && control < 0xC0 {
                    return Err(CompressError::InvalidFormat(
                        "LZMA2 chunk after a dictionary reset must set new properties",
                    ));
                }
                if control >= 0xC0 {
                    // New properties byte follows the size fields
                    let Some(&b) = input.first() else {
                        return Err(CompressError::UnexpectedEof);
                    };
                    input = &input[1..];
                    let p = LzmaProps::from_byte(b)?;
                    props = Some(p);
                    core = Some(LzmaEngine::new(p)?);
                    state_valid = true;
                    need_props = false;
                } else if !state_valid {
                    // State must be reset after uncompressed chunks.
                    if control < 0xA0 {
                        return Err(CompressError::InvalidFormat(
                            "LZMA2 chunk missing state reset",
                        ));
                    }
                    let p = props.ok_or(CompressError::InvalidFormat(
                        "LZMA2 chunk without properties",
                    ))?;
                    core = Some(LzmaEngine::new(p)?);
                    state_valid = true;
                } else if control >= 0xA0 {
                    // State reset (keeps props)
                    if let Some(c) = core.as_mut() {
                        c.reset_state();
                    }
                }
                let c = core.as_mut().unwrap();

                if input.len() < packed {
                    return Err(CompressError::UnexpectedEof);
                }
                let chunk = &input[..packed];
                input = &input[packed..];

                let mut rc = RangeReader::new(chunk)?;
                let before = out.len() as u64;
                c.decode_chunk(
                    &mut rc,
                    &props.unwrap(),
                    &mut out,
                    unpack,
                    dict_base,
                    cap.remaining().min(usize::MAX as u64) as usize,
                )?;
                let emitted = out.len() as u64;
                if emitted > before && !cap.take(emitted - before) {
                    return Ok(Bounded::stopped(out, None, limit));
                }
            } else if control <= 0x02 {
                // Uncompressed chunk (0x01 also resets the dictionary)
                if input.len() < 2 {
                    return Err(CompressError::UnexpectedEof);
                }
                let size = u16::from_be_bytes([input[0], input[1]]) as usize + 1;
                input = &input[2..];
                if input.len() < size {
                    return Err(CompressError::UnexpectedEof);
                }
                if !cap.take(size as u64) {
                    return Ok(Bounded::stopped(out, None, limit));
                }
                out.extend_from_slice(&input[..size]);
                input = &input[size..];
                state_valid = false;
            } else {
                return Err(CompressError::InvalidFormat("invalid LZMA2 control byte"));
            }
        }

        let _ = dict_size;
        Ok(Bounded::complete(out, None, limit))
    }
}

impl Default for LzmaDecoder {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(all(test, feature = "lzma"))]
mod tests {
    use super::*;

    #[test]
    fn test_props_roundtrip() {
        let props = LzmaProps::default();
        assert_eq!(props, LzmaProps::from_byte(props.to_byte()).unwrap());
    }

    /// The literal table is one row of `0x300` probabilities per literal
    /// context, and there are `1 << (lc + lp)` contexts. The row count was
    /// `0x300 << (lc + lp)`, which made the table 768 times the model: the
    /// default properties asked for 9 MiB where the model is 12 KiB.
    #[test]
    fn the_literal_table_is_one_row_per_context() {
        for props in [
            LzmaProps::default(),
            LzmaProps {
                lc: 0,
                lp: 0,
                pb: 0,
            },
            LzmaProps {
                lc: 8,
                lp: 4,
                pb: 0,
            },
        ] {
            let engine = LzmaEngine::new(props).expect("the properties are in range");
            assert_eq!(engine.literal.len(), 1usize << (props.lc + props.lp));
        }
    }

    /// A properties byte of 44 is `lc = 8`, `lp = 4` -- the largest the
    /// specification allows: 4096 contexts, 6 MiB of model. The table used
    /// to be 768 times that, which is four and a half gibibytes out of
    /// twenty-one bytes of input: on a small machine an abort rather than
    /// an answer.
    #[test]
    fn a_header_with_the_worst_properties_byte_is_an_error_and_not_a_bomb() {
        let mut input = alloc::vec![44u8];
        input.extend_from_slice(&(1u32 << 16).to_le_bytes()); // the dictionary size
        input.extend_from_slice(&u64::MAX.to_le_bytes()); // the size: unknown
        input.extend_from_slice(&[0u8; 8]); // a truncated payload
        let err = LzmaDecoder::new()
            .decode(&input)
            .expect_err("the payload is truncated");
        assert!(
            matches!(
                err,
                CompressError::UnexpectedEof
                    | CompressError::CorruptedData(_)
                    | CompressError::InvalidFormat(_)
            ),
            "unexpected error: {err}"
        );
    }

    /// The properties the specification does not allow are refused rather
    /// than modelled: `lc = 8` and `lp = 4` are the limits, and a model
    /// beyond them would ask for a table that does not fit.
    #[test]
    fn properties_outside_the_specification_are_refused() {
        for props in [
            LzmaProps {
                lc: 9,
                lp: 0,
                pb: 0,
            },
            LzmaProps {
                lc: 0,
                lp: 5,
                pb: 0,
            },
            LzmaProps {
                lc: 0,
                lp: 0,
                pb: 5,
            },
        ] {
            assert!(
                matches!(LzmaEngine::new(props), Err(CompressError::InvalidFormat(_))),
                "the properties out of range were not refused"
            );
        }
    }

    /// Vectors produced by CPython's lzma module (liblzma), FORMAT_ALONE.
    #[test]
    fn test_liblzma_vectors_alone() {
        let decoder = LzmaDecoder::new();
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "empty",
                include_bytes!("../../testdata/lzma_alone_empty.bin"),
                include_bytes!("../../testdata/lzma_alone_empty.expected"),
            ),
            (
                "rep_a",
                include_bytes!("../../testdata/lzma_alone_rep_a.bin"),
                include_bytes!("../../testdata/lzma_alone_rep_a.expected"),
            ),
            (
                "text",
                include_bytes!("../../testdata/lzma_alone_text.bin"),
                include_bytes!("../../testdata/lzma_alone_text.expected"),
            ),
            (
                "random",
                include_bytes!("../../testdata/lzma_alone_random.bin"),
                include_bytes!("../../testdata/lzma_alone_random.expected"),
            ),
            (
                "longrange",
                include_bytes!("../../testdata/lzma_alone_longrange.bin"),
                include_bytes!("../../testdata/lzma_alone_longrange.expected"),
            ),
            (
                "shortdist",
                include_bytes!("../../testdata/lzma_alone_shortdist.bin"),
                include_bytes!("../../testdata/lzma_alone_shortdist.expected"),
            ),
        ];
        for (name, compressed, expected) in cases {
            let out = decoder
                .decode(compressed)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&out, expected, "liblzma ALONE vector: {name}");
        }
    }

    /// Vectors produced by CPython's lzma module (liblzma), raw LZMA2.
    ///
    /// Each `.expected` is the plaintext of the matching `.bin` (an earlier
    /// revision pointed these at the ALONE twins, whose payloads differ —
    /// that mismatch, not the decoder, is what the old ignore covered).
    #[test]
    fn test_liblzma_vectors_lzma2() {
        let decoder = LzmaDecoder::new();
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "empty",
                include_bytes!("../../testdata/lzma2_empty.bin"),
                include_bytes!("../../testdata/lzma2_empty.expected"),
            ),
            (
                "rep_a",
                include_bytes!("../../testdata/lzma2_rep_a.bin"),
                include_bytes!("../../testdata/lzma2_rep_a.expected"),
            ),
            (
                "text",
                include_bytes!("../../testdata/lzma2_text.bin"),
                include_bytes!("../../testdata/lzma2_text.expected"),
            ),
            (
                "random",
                include_bytes!("../../testdata/lzma2_random.bin"),
                include_bytes!("../../testdata/lzma2_random.expected"),
            ),
            (
                "longrange",
                include_bytes!("../../testdata/lzma2_longrange.bin"),
                include_bytes!("../../testdata/lzma2_longrange.expected"),
            ),
            (
                "shortdist",
                include_bytes!("../../testdata/lzma2_shortdist.bin"),
                include_bytes!("../../testdata/lzma2_shortdist.expected"),
            ),
        ];
        for (name, compressed, expected) in cases {
            let out = decoder
                .decode_lzma2(compressed, 1 << 26)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&out, expected, "liblzma LZMA2 vector: {name}");
        }
    }

    /// A stream that really does span several LZMA2 chunks.
    ///
    /// liblzma caps a chunk's uncompressed size at 2 MiB, so a stream this
    /// size is split, and every chunk after the first continues the
    /// probability model, the match state and the dictionary. The first
    /// chunk also carries part of its size in the control byte's high five
    /// bits, which is the field a two-byte read drops — that is what this
    /// vector pins.
    ///
    /// Only the compressed stream is stored: the plaintext is a fixed
    /// sequence of five phrases chosen by a linear congruential
    /// generator, and the test rebuilds it rather than committing three
    /// megabytes of fixture.
    #[test]
    fn lzma2_chunked_stream_vector() {
        const PHRASES: [&[u8]; 5] = [
            b"the quick brown fox jumps over the lazy dog. ",
            b"pack my box with five dozen liquor jugs. ",
            b"how vexingly quick daft zebras jump! ",
            b"sphinx of black quartz, judge my vow. ",
            b"the five boxing wizards jump quickly. ",
        ];
        let mut expected: Vec<u8> = Vec::with_capacity(3_000_000);
        let mut x: u32 = 12345;
        while expected.len() < 3_000_000 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            expected.extend_from_slice(PHRASES[(x >> 16) as usize % PHRASES.len()]);
        }
        expected.truncate(3_000_000);

        let out = LzmaDecoder::new()
            .decode_lzma2(include_bytes!("../../testdata/lzma2_chunked.bin"), 1 << 26)
            .expect("liblzma chunked LZMA2 stream");
        assert_eq!(out.len(), expected.len());
        assert_eq!(&out[..], &expected[..]);
    }

    /// An ALONE stream larger than 16 MiB, which is where the decoder
    /// used to fail.
    ///
    /// LZMA1 has no chunk structure, so a match crossing 16 MiB is legal
    /// and was an error anyway: `decode_raw` capped each call's target
    /// at 16 MiB and `decode_chunk` refuses a match crossing its target.
    /// Only the compressed stream is stored; the plaintext is rebuilt
    /// from the same generator the chunked vector uses.
    #[test]
    fn alone_stream_over_sixteen_mib() {
        const PHRASES: [&[u8]; 5] = [
            b"the quick brown fox jumps over the lazy dog. ",
            b"pack my box with five dozen liquor jugs. ",
            b"how vexingly quick daft zebras jump! ",
            b"sphinx of black quartz, judge my vow. ",
            b"the five boxing wizards jump quickly. ",
        ];
        let mut expected: Vec<u8> = Vec::with_capacity(17_000_000);
        let mut x: u32 = 12345;
        while expected.len() < 17_000_000 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            expected.extend_from_slice(PHRASES[(x >> 16) as usize % PHRASES.len()]);
        }
        expected.truncate(17_000_000);

        let out = LzmaDecoder::new()
            .decode(include_bytes!("../../testdata/lzma_alone_over16m.lzma"))
            .expect("ALONE stream over 16 MiB");
        assert_eq!(out.len(), expected.len());
        assert_eq!(&out[..], &expected[..]);
    }

    /// FORMAT_ALONE states the uncompressed size in bytes 5..13, so a
    /// stream that declares more than the cap is refused before a single
    /// byte of it is decoded -- which is the whole point of the field.
    ///
    /// liblzma writes all-ones there when the size is not known ahead of
    /// the stream (every vector in `lzma_alone_*` is one), so the field is
    /// written in here over a real liblzma payload: the claim under test is
    /// that the decoder reads and obeys the declaration, not that it can
    /// encode one.
    #[test]
    fn decode_bounded_refuses_from_the_declared_size() {
        let mut compressed = include_bytes!("../../testdata/lzma_alone_rep_a.bin").to_vec();
        let expected = include_bytes!("../../testdata/lzma_alone_rep_a.expected");
        compressed[5..13].copy_from_slice(&(expected.len() as u64).to_le_bytes());

        let b = LzmaDecoder::new()
            .decode_bounded(&compressed, 1000)
            .expect("bounded");
        assert!(b.capped);
        assert_eq!(b.declared, Some(expected.len() as u64));
        assert!(
            b.bytes.is_empty(),
            "refused early means nothing was decoded"
        );

        let whole = LzmaDecoder::new()
            .decode_bounded(&compressed, expected.len() as u64)
            .expect("exact");
        assert!(!whole.capped);
        assert_eq!(whole.bytes, expected);
    }

    /// A stream whose size is not known has no declaration to refuse from,
    /// so the ceiling is the running one. The bytes it did produce are the
    /// real ones, up to the cap.
    #[test]
    fn decode_bounded_stops_a_stream_that_declares_no_size() {
        let compressed = include_bytes!("../../testdata/lzma_alone_rep_a.bin");
        let expected = include_bytes!("../../testdata/lzma_alone_rep_a.expected");
        assert_eq!(
            u64::from_le_bytes(compressed[5..13].try_into().unwrap()),
            u64::MAX,
            "this vector is only the unknown-size case if liblzma left it unset"
        );
        let b = LzmaDecoder::new()
            .decode_bounded(compressed, 1000)
            .expect("bounded");
        assert!(
            b.capped,
            "a {} byte stream under a 1000 byte cap",
            expected.len()
        );
        assert_eq!(b.declared, None, "nothing was declared");
        assert_eq!(b.bytes, &expected[..1000], "not the real prefix");
    }
}

/// The decoders read untrusted bytes through a range coder whose
/// probabilities steer every branch: truncated input, a bad properties
/// byte, a distance past the dictionary, a chunk that over-declares its
/// size. None may panic.
#[cfg(all(test, feature = "lzma"))]
mod fuzz {
    use super::*;

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            (
                "header_only",
                alloc::vec![0x5D, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            ),
            ("lzma2_end", alloc::vec![0x00]),
            ("lzma2_reset", alloc::vec![0x01, 0x00, 0x00, 0x41]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "lzma", |data| {
            let _ = LzmaDecoder::new().decode(data);
            let _ = LzmaDecoder::new().decode_bounded(data, 1 << 16);
            let props = LzmaProps::default();
            let _ = LzmaDecoder::new().decode_raw(data, props, 1 << 16, None);
            let _ = LzmaDecoder::new().decode_lzma2(data, 1 << 16);
            let _ = LzmaDecoder::new().decode_lzma2_bounded(data, 1 << 16, 1 << 12);
        });
    }
}
