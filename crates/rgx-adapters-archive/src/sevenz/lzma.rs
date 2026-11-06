// SPDX-License-Identifier: Apache-2.0

//! LZMA1 and LZMA2 range-coded compression.
//!
//! Independent reimplementation of the published LZMA algorithm
//! (range coder with 11-bit adaptive probability models, the 12-state
//! match/literal/repeat decision tree, MSB-first and LSB-reverse
//! bit-tree codes) and the LZMA2 chunk layer from the xz/7z
//! specification. The encoder and decoder share the same probability
//! model shapes so a stream written here is readable by liblzma and
//! vice versa; the fixtures under `testdata/lzma_*` are third-party
//! vectors that the tests hold this code against.

use super::error::{CompressError, CompressResult};
use super::graph_mode::GraphMode;
use alloc::vec;
use alloc::vec::Vec;

// ── Public types ────────────────────────────────────────────────────────

/// LZMA properties: literal-context bits, literal-position bits, and
/// position bits.  Packed as `lc + lp*9 + pb*45` in the properties byte.
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
    /// Decode the single-byte property value used in LZMA headers and
    /// LZMA2 chunk descriptors.
    pub fn from_byte(byte: u8) -> Result<Self, CompressError> {
        if byte >= 9 * 5 * 5 {
            return Err(CompressError::InvalidFormat("LZMA properties out of range"));
        }
        Ok(Self {
            lc: byte % 9,
            lp: (byte / 9) % 5,
            pb: byte / 45,
        })
    }

    /// Encode back to the single property byte.
    pub fn to_byte(self) -> u8 {
        self.lc + self.lp * 9 + self.pb * 45
    }
}

pub const LZMA_DICT_MIN: u32 = 1 << 12;
pub const LZMA_DICT_MAX: u32 = 1 << 27;

/// Compression-level knob for the match finder chain length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzmaLevel(pub u8);

impl LzmaLevel {
    pub const FASTEST: Self = Self(0);
    pub const FAST: Self = Self(1);
    pub const NORMAL: Self = Self(3);
    pub const MAX: Self = Self(6);
    pub const ULTRA: Self = Self(9);
}

impl Default for LzmaLevel {
    fn default() -> Self {
        Self::NORMAL
    }
}

// ── Algorithm constants ─────────────────────────────────────────────────

const NUM_STATES: usize = 12;
const NUM_POS_BITS_MAX: usize = 4;
const NUM_LEN_TO_POS_STATES: usize = 4;
const END_POS_MODEL_INDEX: usize = 14;
const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX / 2);
const NUM_POS_SLOTS: usize = 1 << 6;
const ALIGN_BITS: usize = 4;
const ALIGN_TABLE_SIZE: usize = 1 << ALIGN_BITS;
const MATCH_MIN_LEN: usize = 2;

/// Shared probability array for the reverse bit trees of distance
/// slots 4..13.  Slot 13 starts at index 83 and needs 32 entries.
const NUM_POS_SPECIAL: usize = NUM_FULL_DISTANCES - END_POS_MODEL_INDEX + 1; // 115

const PROB_INIT: u16 = 1024;
const PROB_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 2048;
const MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

// ── Range encoder ───────────────────────────────────────────────────────

struct RangeEncoder {
    range: u64,
    low: u64,
    cache: u8,
    cache_size: u64,
    output: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        Self {
            range: 0xFFFF_FFFF,
            low: 0,
            cache: 0,
            cache_size: 1,
            output: Vec::new(),
        }
    }

    fn normalize(&mut self) {
        if self.range < TOP_VALUE as u64 {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut temp = self.cache;
            let mut n = self.cache_size;
            while n > 0 {
                self.output.push(temp.wrapping_add(carry));
                temp = 0xFF;
                n -= 1;
            }
            self.cache_size = 0;
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let bound = (self.range >> PROB_BITS) * (*prob as u64);
        if bit == 0 {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - *prob as u32) >> MOVE_BITS) as u16;
        } else {
            self.low += bound;
            self.range -= bound;
            *prob -= *prob >> MOVE_BITS;
        }
        self.normalize();
    }

    /// MSB-first bit tree (lengths, pos slots, literals).
    fn encode_bit_tree(&mut self, probs: &mut [u16], value: u32, bits: u32) {
        let mut m = 1u32;
        for i in (0..bits).rev() {
            let bit = (value >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    fn encode_direct(&mut self, value: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.range >>= 1;
            self.low += self.range & (((value >> i) & 1) as u64 * 0xFFFF_FFFF_FFFF_FFFF);
            self.normalize();
        }
    }

    /// LSB-first (reverse) bit tree for align and shared distance slots.
    fn encode_reverse(&mut self, probs: &mut [u16], value: u32, bits: u32) {
        let mut m = 1;
        for i in 0..bits {
            let bit = (value >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.output
    }
}

// ── Range decoder ───────────────────────────────────────────────────────

/// Range decoder for a raw LZMA1 stream: the payload is a leading 0x00
/// byte followed by a 4-byte big-endian initial code.
struct RangeDecoder<'a> {
    input: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(input: &'a [u8]) -> CompressResult<Self> {
        if input.len() < 5 {
            return Err(CompressError::UnexpectedEof);
        }
        let code = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
        Ok(Self {
            input,
            pos: 5,
            range: u32::MAX,
            code,
        })
    }

    #[inline]
    fn next_byte(&mut self) -> u32 {
        let b = if self.pos < self.input.len() {
            self.input[self.pos]
        } else {
            0
        };
        self.pos += 1;
        b as u32
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.code = (self.code << 8) | self.next_byte();
            self.range <<= 8;
        }
    }

    #[inline]
    fn decode_bit(&mut self, prob: &mut u16) -> u32 {
        let bound = (self.range >> PROB_BITS) * (*prob as u32);
        if self.code < bound {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - *prob as u32) >> MOVE_BITS) as u16;
            self.normalize();
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= *prob >> MOVE_BITS;
            self.normalize();
            1
        }
    }

    #[inline]
    fn decode_direct(&mut self, bits: u32) -> u32 {
        let mut result = 0u32;
        for _ in 0..bits {
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            result = (result << 1).wrapping_add(t.wrapping_add(1));
            self.normalize();
        }
        result
    }

    fn decode_bit_tree(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1u32;
        for _ in 0..bits {
            let b = self.decode_bit(&mut probs[m as usize]);
            m = (m << 1) | b;
        }
        m - (1 << bits)
    }

    fn decode_bit_tree_reverse(&mut self, probs: &mut [u16], bits: u32) -> u32 {
        let mut m = 1u32;
        let mut result = 0u32;
        for i in 0..bits {
            let b = self.decode_bit(&mut probs[m as usize]);
            m = (m << 1) | b;
            result |= b << i;
        }
        result
    }
}

// ── State machine ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct LzmaState {
    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
}

impl LzmaState {
    fn new() -> Self {
        Self {
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
        }
    }

    fn update_literal(&mut self) {
        self.state = if self.state < 4 {
            0
        } else if self.state < 10 {
            self.state - 3
        } else {
            self.state - 6
        };
    }

    fn update_match(&mut self) {
        self.state = if self.state < 7 { 7 } else { 10 };
    }

    fn update_rep(&mut self) {
        self.state = if self.state < 7 { 8 } else { 11 };
    }

    fn update_short_rep(&mut self) {
        self.state = if self.state < 7 { 9 } else { 11 };
    }

    fn is_char(&self) -> bool {
        self.state < 7
    }

    fn update_reps(&mut self, dist: u32) {
        self.rep3 = self.rep2;
        self.rep2 = self.rep1;
        self.rep1 = self.rep0;
        self.rep0 = dist;
    }
}

// ── Length coder models ─────────────────────────────────────────────────

#[derive(Clone)]
struct LenModels {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; 16],
    mid: [[u16; 8]; 16],
    high: [u16; 256],
}

impl LenModels {
    fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; 8]; 16],
            mid: [[PROB_INIT; 8]; 16],
            high: [PROB_INIT; 256],
        }
    }

    fn encode(&mut self, rc: &mut RangeEncoder, pos_state: usize, len: usize) {
        if len < 8 {
            rc.encode_bit(&mut self.choice, 0);
            rc.encode_bit_tree(&mut self.low[pos_state][..], len as u32, 3);
        } else if len < 16 {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 0);
            rc.encode_bit_tree(&mut self.mid[pos_state][..], (len - 8) as u32, 3);
        } else {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 1);
            rc.encode_bit_tree(&mut self.high[..], (len - 16) as u32, 8);
        }
    }

    fn decode(&mut self, rc: &mut RangeDecoder, pos_state: usize) -> CompressResult<usize> {
        if rc.decode_bit(&mut self.choice) == 0 {
            Ok(rc.decode_bit_tree(&mut self.low[pos_state][..], 3) as usize)
        } else if rc.decode_bit(&mut self.choice2) == 0 {
            Ok(8 + rc.decode_bit_tree(&mut self.mid[pos_state][..], 3) as usize)
        } else {
            Ok(16 + rc.decode_bit_tree(&mut self.high[..], 8) as usize)
        }
    }
}

// ── Shared probability model set ────────────────────────────────────────

struct LzmaCore {
    st: LzmaState,
    is_match: [[u16; NUM_POS_BITS_MAX + 1]; NUM_STATES],
    is_rep: [u16; NUM_STATES],
    is_rep0: [u16; NUM_STATES],
    is_rep1: [u16; NUM_STATES],
    is_rep2: [u16; NUM_STATES],
    is_rep0_long: [[u16; NUM_POS_BITS_MAX + 1]; NUM_STATES],
    rep_len: LenModels,
    match_len: LenModels,
    literal: Vec<[u16; 0x300]>,
    pos_slot: [[u16; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES],
    pos_special: [u16; NUM_POS_SPECIAL],
    align: [u16; ALIGN_TABLE_SIZE],
}

impl LzmaCore {
    fn new(props: LzmaProps) -> Self {
        Self {
            st: LzmaState::new(),
            is_match: [[PROB_INIT; NUM_POS_BITS_MAX + 1]; NUM_STATES],
            is_rep: [PROB_INIT; NUM_STATES],
            is_rep0: [PROB_INIT; NUM_STATES],
            is_rep1: [PROB_INIT; NUM_STATES],
            is_rep2: [PROB_INIT; NUM_STATES],
            is_rep0_long: [[PROB_INIT; NUM_POS_BITS_MAX + 1]; NUM_STATES],
            rep_len: LenModels::new(),
            match_len: LenModels::new(),
            literal: vec![[PROB_INIT; 0x300]; 1 << (props.lc + props.lp)],
            pos_slot: [[PROB_INIT; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES],
            pos_special: [PROB_INIT; NUM_POS_SPECIAL],
            align: [PROB_INIT; ALIGN_TABLE_SIZE],
        }
    }

    /// Reset every probability model and the state machine (LZMA2 state
    /// reset).  The literal arena is refilled in place so a chunk reset
    /// does not reallocate.
    fn reset_state(&mut self) {
        self.st = LzmaState::new();
        self.is_match = [[PROB_INIT; NUM_POS_BITS_MAX + 1]; NUM_STATES];
        self.is_rep = [PROB_INIT; NUM_STATES];
        self.is_rep0 = [PROB_INIT; NUM_STATES];
        self.is_rep1 = [PROB_INIT; NUM_STATES];
        self.is_rep2 = [PROB_INIT; NUM_STATES];
        self.is_rep0_long = [[PROB_INIT; NUM_POS_BITS_MAX + 1]; NUM_STATES];
        self.rep_len = LenModels::new();
        self.match_len = LenModels::new();
        self.literal.fill([PROB_INIT; 0x300]);
        self.pos_slot = [[PROB_INIT; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES];
        self.pos_special = [PROB_INIT; NUM_POS_SPECIAL];
        self.align = [PROB_INIT; ALIGN_TABLE_SIZE];
    }

    fn pos_mask(props: &LzmaProps) -> usize {
        (1 << props.pb) - 1
    }

    /// Literal probability context index from position and previous byte.
    /// `dict_base` is where the current dictionary window starts (LZMA2
    /// resets the position counter with the dictionary).
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

    /// Decode symbols until `unpack` more bytes are produced past the
    /// current length of `out`.  Returns `true` when the end-of-stream
    /// marker (distance 0xFFFF_FFFF) was reached.
    fn decode_chunk(
        &mut self,
        rc: &mut RangeDecoder,
        props: &LzmaProps,
        out: &mut Vec<u8>,
        unpack: usize,
        dict_base: usize,
    ) -> CompressResult<bool> {
        let pos_mask = Self::pos_mask(props);
        let target = out.len() + unpack;
        while out.len() < target {
            let pos_state = (out.len() - dict_base) & pos_mask;

            if rc.decode_bit(&mut self.is_match[self.st.state][pos_state]) == 0 {
                // ── Literal ────────────────────────────────────────────
                let probs = &mut self.literal[Self::lit_state(props, out, out.len(), dict_base)];
                let mut symbol = 1usize;
                if self.st.is_char() {
                    while symbol < 0x100 {
                        let b = rc.decode_bit(&mut probs[symbol]) as usize;
                        symbol = (symbol << 1) | b;
                    }
                } else {
                    let dist = self.st.rep0 as usize;
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
                        let b = rc.decode_bit(&mut probs[offset + match_bit + symbol]) as usize;
                        symbol = (symbol << 1) | b;
                        offset &= !(match_bit ^ (b * 0x100));
                    }
                }
                out.push((symbol - 0x100) as u8);
                self.st.update_literal();
                continue;
            }

            // ── Match or repeat ────────────────────────────────────────
            let mut len;
            if rc.decode_bit(&mut self.is_rep[self.st.state]) != 0 {
                // Repeat distance
                if rc.decode_bit(&mut self.is_rep0[self.st.state]) == 0 {
                    if rc.decode_bit(&mut self.is_rep0_long[self.st.state][pos_state]) == 0 {
                        // Short repeat: one byte at rep0
                        self.st.update_short_rep();
                        let dist = self.st.rep0 as usize;
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
                    if rc.decode_bit(&mut self.is_rep1[self.st.state]) == 0 {
                        dist = self.st.rep1;
                    } else if rc.decode_bit(&mut self.is_rep2[self.st.state]) == 0 {
                        dist = self.st.rep2;
                        self.st.rep2 = self.st.rep1;
                    } else {
                        dist = self.st.rep3;
                        self.st.rep3 = self.st.rep2;
                        self.st.rep2 = self.st.rep1;
                    }
                    self.st.rep1 = self.st.rep0;
                    self.st.rep0 = dist;
                }
                len = self.rep_len.decode(rc, pos_state)? + MATCH_MIN_LEN;
                self.st.update_rep();
            } else {
                // Simple match: new distance
                self.st.rep3 = self.st.rep2;
                self.st.rep2 = self.st.rep1;
                self.st.rep1 = self.st.rep0;
                len = self.match_len.decode(rc, pos_state)? + MATCH_MIN_LEN;
                self.st.update_match();

                let len_state = (len - MATCH_MIN_LEN).min(NUM_LEN_TO_POS_STATES - 1);
                let slot = rc.decode_bit_tree(&mut self.pos_slot[len_state][..], 6) as usize;

                let mut dist;
                if slot < 4 {
                    dist = slot as u32;
                } else {
                    let num_direct = (slot >> 1) - 1;
                    dist = (2 | (slot & 1) as u32) << num_direct;
                    if slot < END_POS_MODEL_INDEX {
                        let start = (dist - slot as u32) as usize;
                        dist += rc.decode_bit_tree_reverse(
                            &mut self.pos_special[start..],
                            num_direct as u32,
                        );
                    } else {
                        dist += rc.decode_direct((num_direct - ALIGN_BITS) as u32) << ALIGN_BITS;
                        dist += rc.decode_bit_tree_reverse(&mut self.align[..], ALIGN_BITS as u32);
                    }
                }

                if dist == u32::MAX {
                    return Ok(true);
                }
                self.st.rep0 = dist;
            }

            // Copy match bytes.  LZMA distances are zero-based.
            let dist = self.st.rep0 as usize;
            if dist + 1 > out.len() - dict_base {
                return Err(CompressError::InvalidFormat(
                    "LZMA match distance out of range",
                ));
            }
            if out.len() + len > target {
                return Err(CompressError::InvalidFormat("LZMA chunk size mismatch"));
            }
            let start = out.len() - dist - 1;
            out.reserve(len);
            for i in 0..len {
                out.push(out[start + i]);
            }
        }
        Ok(false)
    }
}

// ── Encoder ─────────────────────────────────────────────────────────────

/// LZMA1 encoder: produces a legacy ALONE-format stream (1-byte props,
/// 4-byte LE dict size, 8-byte LE uncompressed size, range-coded payload
/// terminated by the end-of-stream marker).
pub struct LzmaEncoder {
    props: LzmaProps,
    dict_size: u32,
    level: LzmaLevel,
    graph_mode: GraphMode,
}

impl LzmaEncoder {
    pub fn new() -> Self {
        Self::with_settings(LzmaProps::default(), 1 << 20, LzmaLevel::NORMAL)
    }

    pub fn with_settings(props: LzmaProps, dict_size: u32, level: LzmaLevel) -> Self {
        Self {
            props,
            dict_size: dict_size.clamp(LZMA_DICT_MIN, LZMA_DICT_MAX),
            level,
            graph_mode: GraphMode::default(),
        }
    }

    /// Select match-finding strategy.  The range coder is too sensitive
    /// to initial probabilities for match-finder heuristics to change
    /// the probability models, so this is kept for API consistency.
    pub fn with_graph_mode(mut self, mode: GraphMode) -> Self {
        self.graph_mode = mode;
        self
    }

    pub fn encode(&self, input: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();

        // Header: props byte, dict size (LE u32), uncompressed size (LE u64).
        output.push(self.props.to_byte());
        output.extend_from_slice(&self.dict_size.to_le_bytes());
        output.extend_from_slice(&(input.len() as u64).to_le_bytes());

        if input.is_empty() {
            return output;
        }

        let pb = self.props.pb as usize;
        let lp = self.props.lp as usize;
        let lc = self.props.lc as usize;
        let _ = &self.graph_mode;

        let pos_mask = (1 << pb) - 1;
        let literal_pos_mask = (1 << lp) - 1;

        // Every probability model starts at PROB_INIT: the decoder
        // initializes every model at PROB_INIT unconditionally, so any
        // encoder-side bias would desynchronize the stream.
        let mut is_match = [[PROB_INIT; NUM_POS_BITS_MAX + 1]; NUM_STATES];
        let mut is_rep = [PROB_INIT; NUM_STATES];
        let mut is_rep0 = [PROB_INIT; NUM_STATES];
        let mut is_rep1 = [PROB_INIT; NUM_STATES];
        let mut is_rep2 = [PROB_INIT; NUM_STATES];
        let mut rep_len_encoder = LenModels::new();
        let mut match_len_encoder = LenModels::new();
        let mut literal_probs = vec![[PROB_INIT; 0x300]; 1 << (lc + lp)];
        let mut pos_slot = [[PROB_INIT; NUM_POS_SLOTS]; NUM_LEN_TO_POS_STATES];
        let mut pos_special = [PROB_INIT; NUM_POS_SPECIAL];
        let mut align = [PROB_INIT; ALIGN_TABLE_SIZE];

        // Match finder state
        let max_chain = match self.level.0 {
            0..=2 => 4,
            3..=5 => 32,
            6..=7 => 128,
            _ => 256,
        };
        let max_dist = self.dict_size as usize;

        let hash_size = 1 << 16;
        let mut hash_table: Vec<i32> = vec![-1; hash_size];
        let mut hash_chain: Vec<i32> = vec![-1; input.len().max(1)];

        let mut rc = RangeEncoder::new();
        let mut state = LzmaState::new();
        let mut pos = 0;

        while pos < input.len() {
            let pos_state = pos & pos_mask;

            let (match_len, match_dist) = if pos + 2 < input.len() {
                self.find_match(input, pos, max_dist, max_chain, &hash_table, &hash_chain)
            } else {
                (0, 0)
            };

            if pos + 2 < input.len() {
                let h = Self::hash(&input[pos..pos + 3]);
                hash_chain[pos] = hash_table[h];
                hash_table[h] = pos as i32;
            }

            if match_len > MATCH_MIN_LEN {
                // Encode a match
                rc.encode_bit(&mut is_match[state.state][pos_state], 1);
                rc.encode_bit(&mut is_rep[state.state], 0);

                state.update_match();
                match_len_encoder.encode(&mut rc, pos_state, match_len - MATCH_MIN_LEN);

                let dist_val = match_dist - 1;
                let len_state = (match_len - MATCH_MIN_LEN).min(NUM_LEN_TO_POS_STATES - 1);
                let slot_val = Self::get_pos_slot(dist_val);
                rc.encode_bit_tree(&mut pos_slot[len_state][..], slot_val as u32, 6);

                if slot_val >= 4 {
                    let num_direct = (slot_val >> 1) - 1;
                    let base = ((2 | (slot_val & 1)) as u32) << num_direct;

                    if slot_val < END_POS_MODEL_INDEX {
                        let start = (base - slot_val as u32) as usize;
                        rc.encode_reverse(
                            &mut pos_special[start..],
                            dist_val - base,
                            num_direct as u32,
                        );
                    } else {
                        rc.encode_direct(
                            (dist_val - base) >> ALIGN_BITS,
                            (num_direct - ALIGN_BITS) as u32,
                        );
                        rc.encode_reverse(
                            &mut align[..],
                            dist_val & ((1 << ALIGN_BITS) - 1),
                            ALIGN_BITS as u32,
                        );
                    }
                }

                state.update_reps(dist_val);

                for i in 1..match_len {
                    if pos + i + 2 < input.len() {
                        let h = Self::hash(&input[pos + i..pos + i + 3]);
                        hash_chain[pos + i] = hash_table[h];
                        hash_table[h] = (pos + i) as i32;
                    }
                }

                pos += match_len;
            } else {
                // Encode a literal
                rc.encode_bit(&mut is_match[state.state][pos_state], 0);

                let lit_state = ((pos & literal_pos_mask) << lc)
                    + (if pos > 0 {
                        input[pos - 1] as usize >> (8 - lc)
                    } else {
                        0
                    });
                let probs = &mut literal_probs[lit_state];

                let byte = input[pos];
                let mut byte_val = byte;
                let mut symbol = 1;

                if state.is_char() {
                    for i in 0..8 {
                        rc.encode_bit(&mut probs[symbol], ((byte >> (7 - i)) & 1) as u32);
                        symbol = (symbol << 1) | ((byte >> (7 - i)) & 1) as usize;
                    }
                } else {
                    let match_byte_orig = input[pos - 1 - state.rep0 as usize];
                    let mut match_byte = match_byte_orig as usize;
                    let mut offset: usize = 0x100;

                    for _ in 0..8 {
                        match_byte <<= 1;
                        let match_bit = match_byte & offset;
                        let byte_bit = ((byte_val >> 7) & 1) as usize;
                        rc.encode_bit(&mut probs[offset + match_bit + symbol], byte_bit as u32);
                        symbol = (symbol << 1) | byte_bit;
                        offset &= !(match_bit ^ (byte_bit * 0x100));
                        byte_val <<= 1;
                    }
                }

                state.update_literal();
                pos += 1;
            }
        }

        // End-of-stream marker: match length 2, distance 0xFFFF_FFFF.
        let pos_state = pos & pos_mask;
        rc.encode_bit(&mut is_match[state.state][pos_state], 1);
        rc.encode_bit(&mut is_rep[state.state], 0);
        match_len_encoder.encode(&mut rc, pos_state, 0);
        rc.encode_bit_tree(&mut pos_slot[0][..], (NUM_POS_SLOTS - 1) as u32, 6);
        // Slot 63: 26 direct bits of all ones, then 4 align bits of all ones.
        rc.encode_direct(0x3FF_FFFF, 26);
        rc.encode_reverse(
            &mut align[..],
            (ALIGN_TABLE_SIZE - 1) as u32,
            ALIGN_BITS as u32,
        );

        output.extend(rc.finish());
        output
    }

    fn find_match(
        &self,
        data: &[u8],
        pos: usize,
        max_dist: usize,
        max_chain: usize,
        hash_table: &[i32],
        hash_chain: &[i32],
    ) -> (usize, u32) {
        if pos + 3 > data.len() {
            return (0, 0);
        }

        let h = Self::hash(&data[pos..pos + 3]);
        let mut best_len = 2;
        let mut best_dist = 0u32;

        let mut chain = hash_table[h];
        let mut count = 0;

        while chain >= 0 && count < max_chain {
            let match_pos = chain as usize;
            let dist = pos - match_pos;

            if dist > max_dist || dist == 0 {
                break;
            }

            let mut len = 0;
            let max_len = (data.len() - pos).min(273);
            while len < max_len && data[match_pos + len] == data[pos + len] {
                len += 1;
            }

            if len > best_len {
                best_len = len;
                best_dist = dist as u32;
                if len >= 128 {
                    break;
                }
            }

            chain = hash_chain[match_pos];
            count += 1;
        }

        if best_len > MATCH_MIN_LEN {
            (best_len, best_dist)
        } else {
            (0, 0)
        }
    }

    #[inline]
    fn hash(data: &[u8]) -> usize {
        let v = (data[0] as usize) | ((data[1] as usize) << 8) | ((data[2] as usize) << 16);
        let k = 0x9E37_79B9;
        let h = v.wrapping_mul(k);
        (h ^ (h >> 16)) & 0xFFFF
    }

    /// Position slot per the LZMA spec:
    /// `slot = 2*floor(log2(dist)) + second-highest-bit(dist)`.
    fn get_pos_slot(dist: u32) -> usize {
        if dist < 4 {
            dist as usize
        } else {
            let n = 31 - dist.leading_zeros();
            ((n << 1) | ((dist >> (n - 1)) & 1)) as usize
        }
    }
}

impl Default for LzmaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Decoder ─────────────────────────────────────────────────────────────

/// LZMA decoder: legacy `.lzma` (ALONE) header format, raw LZMA1 streams
/// and LZMA2 chunk streams.
pub struct LzmaDecoder;

impl LzmaDecoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode a legacy `.lzma` (FORMAT_ALONE) stream: 1-byte props,
    /// 4-byte LE dictionary size, 8-byte LE uncompressed size
    /// (`u64::MAX` = unknown).
    pub fn decode(&self, input: &[u8]) -> CompressResult<Vec<u8>> {
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

        if unpack_size == Some(0) && input.len() == 13 {
            return Ok(Vec::new());
        }

        self.decode_raw(&input[13..], props, dict_size, unpack_size)
    }

    /// Decode a raw LZMA1 stream (no header), as stored inside 7z
    /// archives.  When `unpack_size` is `Some(n)` the stream may omit
    /// the end-of-stream marker because the container already stated
    /// the byte count; the decoder then aims at exactly `n` bytes.
    /// When `unpack_size` is `None` the only terminator is the marker.
    pub fn decode_raw(
        &self,
        input: &[u8],
        props: LzmaProps,
        dict_size: u32,
        unpack_size: Option<u64>,
    ) -> CompressResult<Vec<u8>> {
        let mut rc = RangeDecoder::new(input)?;
        let mut core = LzmaCore::new(props);
        let mut out: Vec<u8> = Vec::with_capacity(unpack_size.unwrap_or(0).min(1 << 26) as usize);

        let unpack = match unpack_size {
            Some(n) => n as usize,
            None => usize::MAX,
        };
        loop {
            let remaining = unpack.saturating_sub(out.len());
            if remaining == 0 {
                break;
            }
            // When the size is known, aim at exactly the remaining bytes:
            // the stream usually carries no end marker because the
            // container already said how many bytes to expect.  Aiming
            // past that overshoots the payload and runs off the end of
            // the input.  When the size is unknown the only terminator
            // is the end-of-stream marker.
            let chunk = match unpack_size {
                Some(_) => remaining,
                None => usize::MAX,
            };
            let ended = core.decode_chunk(&mut rc, &props, &mut out, chunk, 0)?;
            if ended || out.len() >= unpack {
                break;
            }
        }
        if let Some(n) = unpack_size {
            if out.len() != n as usize {
                return Err(CompressError::UnexpectedEof);
            }
        }
        let _ = dict_size;
        Ok(out)
    }

    /// Decode a raw LZMA2 chunk stream (as used by xz and 7z).
    pub fn decode_lzma2(&self, mut input: &[u8], dict_size: u32) -> CompressResult<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut props: Option<LzmaProps> = None;
        let mut core: Option<LzmaCore> = None;
        let mut need_dict_reset = true;
        // After an uncompressed chunk the LZMA state is invalid until a
        // chunk resets it (control >= 0xA0).
        let mut state_valid = false;
        // A dictionary reset requires properties, and only a chunk that
        // carries them clears the requirement.  Control >= 0xC0 does
        // both at once, so the only reset that leaves the flag standing
        // is 0x01 (reset with a single uncompressed byte and no
        // properties).  The next LZMA chunk must then set new properties.
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
                need_dict_reset = false;
                dict_base = out.len();
                need_props = true;
            } else if need_dict_reset {
                return Err(CompressError::InvalidFormat(
                    "LZMA2 stream missing dictionary reset",
                ));
            }

            if control >= 0x80 {
                // LZMA chunk: [control][unpack size hi 5 bits + 2 BE
                // bytes][packed size u16 BE], then payload, then the
                // properties byte when control >= 0xC0.
                if input.len() < 4 {
                    return Err(CompressError::UnexpectedEof);
                }
                let unpack = ((((control & 0x1F) as usize) << 16)
                    | u16::from_be_bytes([input[0], input[1]]) as usize)
                    + 1;
                let packed = u16::from_be_bytes([input[2], input[3]]) as usize + 1;
                input = &input[4..];

                if need_props && control < 0xC0 {
                    return Err(CompressError::InvalidFormat(
                        "LZMA2 chunk after a dictionary reset must set new properties",
                    ));
                }
                if control >= 0xC0 {
                    let Some(&b) = input.first() else {
                        return Err(CompressError::UnexpectedEof);
                    };
                    input = &input[1..];
                    let p = LzmaProps::from_byte(b)?;
                    props = Some(p);
                    core = Some(LzmaCore::new(p));
                    state_valid = true;
                    need_props = false;
                } else if !state_valid {
                    if control < 0xA0 {
                        return Err(CompressError::InvalidFormat(
                            "LZMA2 chunk missing state reset",
                        ));
                    }
                    let p = props.ok_or(CompressError::InvalidFormat(
                        "LZMA2 chunk without properties",
                    ))?;
                    core = Some(LzmaCore::new(p));
                    state_valid = true;
                } else if control >= 0xA0 {
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

                let mut rc = RangeDecoder::new(chunk)?;
                c.decode_chunk(&mut rc, &props.unwrap(), &mut out, unpack, dict_base)?;
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
                out.extend_from_slice(&input[..size]);
                input = &input[size..];
                state_valid = false;
            } else {
                return Err(CompressError::InvalidFormat("invalid LZMA2 control byte"));
            }
        }

        let _ = dict_size;
        Ok(out)
    }
}

impl Default for LzmaDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_props_roundtrip() {
        let props = LzmaProps::default();
        assert_eq!(props, LzmaProps::from_byte(props.to_byte()).unwrap());
    }

    #[test]
    fn test_empty() {
        let encoder = LzmaEncoder::new();
        let compressed = encoder.encode(b"");
        assert!(compressed.len() >= 13);

        let decoder = LzmaDecoder::new();
        let decompressed = decoder.decode(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn test_repeated_bytes() {
        let encoder = LzmaEncoder::with_settings(LzmaProps::default(), 1 << 16, LzmaLevel::ULTRA);

        let input = vec![0u8; 10000];
        let compressed = encoder.encode(&input);
        let ratio = compressed.len() as f64 / input.len() as f64;

        // Should compress to < 1% for repeated bytes
        assert!(ratio < 0.01, "Expected <1%, got {:.2}%", ratio * 100.0);
    }

    #[test]
    fn test_repeated_pattern() {
        let encoder = LzmaEncoder::with_settings(LzmaProps::default(), 1 << 16, LzmaLevel::ULTRA);

        let input: Vec<u8> = (0..100).cycle().take(10000).collect();
        let compressed = encoder.encode(&input);
        let ratio = compressed.len() as f64 / input.len() as f64;

        // Should compress well for repeating pattern
        assert!(ratio < 0.03, "Expected <3%, got {:.2}%", ratio * 100.0);
    }

    #[test]
    fn test_text() {
        let encoder = LzmaEncoder::new();

        let input = b"Hello, World! This is a test of the LZMA compression algorithm. ".repeat(100);
        let compressed = encoder.encode(&input);
        let ratio = compressed.len() as f64 / input.len() as f64;

        // Text should compress well
        assert!(ratio < 0.10, "Expected <10%, got {:.2}%", ratio * 100.0);
    }

    #[test]
    fn test_random_data() {
        let encoder = LzmaEncoder::new();

        // Pseudo-random data (not truly random, but hard to compress)
        let input: Vec<u8> = (0..10000)
            .map(|i| ((i as i64 * 1103515245 + 12345) >> 16) as u8)
            .collect();
        let compressed = encoder.encode(&input);

        // Random data should not expand significantly
        let ratio = compressed.len() as f64 / input.len() as f64;
        assert!(
            ratio < 1.5,
            "Random data should not expand much, got {:.2}%",
            ratio * 100.0
        );
    }

    #[test]
    fn test_pos_slot() {
        assert_eq!(LzmaEncoder::get_pos_slot(0), 0);
        assert_eq!(LzmaEncoder::get_pos_slot(1), 1);
        assert_eq!(LzmaEncoder::get_pos_slot(2), 2);
        assert_eq!(LzmaEncoder::get_pos_slot(3), 3);
        assert_eq!(LzmaEncoder::get_pos_slot(4), 4);
        assert_eq!(LzmaEncoder::get_pos_slot(5), 4);
        assert_eq!(LzmaEncoder::get_pos_slot(6), 5);
        assert_eq!(LzmaEncoder::get_pos_slot(8), 6);
        assert_eq!(LzmaEncoder::get_pos_slot(12), 7);
        assert_eq!(LzmaEncoder::get_pos_slot(16), 8);
        assert_eq!(LzmaEncoder::get_pos_slot(127), 13);
        assert_eq!(LzmaEncoder::get_pos_slot(128), 14);
        assert_eq!(LzmaEncoder::get_pos_slot(0xFFFFFFFF), 63);
    }

    #[test]
    fn test_roundtrip_varied() {
        let decoder = LzmaDecoder::new();
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![b'a'; 10000],
            b"Hello, World! This is a test of the LZMA compression algorithm. ".repeat(50),
            (0..5000u32)
                .map(|i| (i.wrapping_mul(1103515245).wrapping_add(12345) >> 16) as u8)
                .collect(),
            {
                // Long-range repeats to exercise direct-bit distances
                let mut v: Vec<u8> = (0..8192u32)
                    .map(|i| (i.wrapping_mul(2654435761)) as u8)
                    .collect();
                let tail: Vec<u8> = v[..300].to_vec();
                v.extend_from_slice(&vec![b'x'; 5000]);
                v.extend_from_slice(&tail);
                v
            },
        ];
        for (i, input) in cases.iter().enumerate() {
            let compressed =
                LzmaEncoder::with_settings(LzmaProps::default(), 1 << 20, LzmaLevel::ULTRA)
                    .encode(input);
            let out = decoder
                .decode(&compressed)
                .unwrap_or_else(|e| panic!("case {i}: {e}"));
            assert_eq!(&out, input, "roundtrip case {i}");
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
    #[test]
    fn test_liblzma_vectors_lzma2() {
        let decoder = LzmaDecoder::new();
        let cases: &[(&str, &[u8], &[u8])] = &[
            (
                "empty",
                include_bytes!("../../testdata/lzma2_empty.bin"),
                include_bytes!("../../testdata/lzma_alone_empty.expected"),
            ),
            (
                "rep_a",
                include_bytes!("../../testdata/lzma2_rep_a.bin"),
                include_bytes!("../../testdata/lzma_alone_rep_a.expected"),
            ),
            (
                "text",
                include_bytes!("../../testdata/lzma2_text.bin"),
                include_bytes!("../../testdata/lzma_alone_text.expected"),
            ),
            (
                "random",
                include_bytes!("../../testdata/lzma2_random.bin"),
                include_bytes!("../../testdata/lzma_alone_random.expected"),
            ),
            (
                "longrange",
                include_bytes!("../../testdata/lzma2_longrange.bin"),
                include_bytes!("../../testdata/lzma_alone_longrange.expected"),
            ),
            (
                "shortdist",
                include_bytes!("../../testdata/lzma2_shortdist.bin"),
                include_bytes!("../../testdata/lzma_alone_shortdist.expected"),
            ),
        ];
        for (name, compressed, expected) in cases {
            let out = decoder
                .decode_lzma2(compressed, 1 << 26)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(&out, expected, "liblzma LZMA2 vector: {name}");
        }
    }

    /// A 7z folder's LZMA1 stream, straight out of 7-Zip.
    ///
    /// It carries no end-of-stream marker: the container states the size,
    /// so the payload simply stops. The decoder aimed 16 MiB ahead
    /// regardless, produced the bytes, kept going, and ran off the end of
    /// the input. Every 7z archive using the LZMA1 coder failed this way,
    /// and rgx reported neither a match nor an error -- the adapter turns
    /// a failure into searchable text, so the file looked empty.
    ///
    /// liblzma decodes these 216 bytes to the 200 below, so the pair is a
    /// third-party vector rather than a matched roundtrip.
    #[test]
    fn lzma1_stream_with_no_end_marker() {
        let raw = include_bytes!("../../testdata/lzma1_7z_nomarker.bin");
        let expected = include_bytes!("../../testdata/lzma1_7z_nomarker.expected");
        let props = LzmaProps::from_byte(0x5d).unwrap();
        let out = LzmaDecoder::new()
            .decode_raw(raw, props, 4096, Some(expected.len() as u64))
            .expect("a 7z LZMA1 stream with no end marker");
        assert_eq!(out, *expected, "decoded bytes differ from the original");
    }

    #[test]
    fn test_lzma2_multi_chunk() {
        // A large input forces liblzma to emit several LZMA2 chunks
        // (chunk unpack size is capped at 2 MiB).
        let mut data = Vec::new();
        let mut x: u32 = 12345;
        for _ in 0..5_000_000 {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            data.push((x >> 16) as u8);
        }
        let compressed = LzmaEncoder::new().encode(&data);
        let decoder = LzmaDecoder::new();
        let out = decoder.decode(&compressed).unwrap();
        assert_eq!(out, data);
    }

    // ── New tests for shapes the old suite missed ────────────────────

    #[test]
    fn rejects_props_byte_out_of_range() {
        assert!(LzmaProps::from_byte(9 * 5 * 5).is_err());
        assert!(LzmaProps::from_byte(255).is_err());
        assert!(LzmaProps::from_byte(224).is_ok());
    }

    #[test]
    fn decode_raw_truncated_input() {
        assert!(matches!(
            LzmaDecoder::new().decode_raw(&[], LzmaProps::default(), 4096, Some(10)),
            Err(CompressError::UnexpectedEof)
        ));
        assert!(matches!(
            LzmaDecoder::new().decode_raw(&[0, 0, 0], LzmaProps::default(), 4096, Some(10)),
            Err(CompressError::UnexpectedEof)
        ));
    }

    #[test]
    fn lzma2_rejects_missing_dictionary_reset() {
        // An LZMA chunk with no preceding dictionary reset.
        let chunk = [0x80u8, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            LzmaDecoder::new().decode_lzma2(&chunk, 1 << 16),
            Err(CompressError::InvalidFormat(_))
        ));
    }

    #[test]
    fn lzma2_rejects_lzma_chunk_after_reset_without_props() {
        // 0x01 = dictionary reset (with an uncompressed byte), then a
        // 0xA0 LZMA chunk that resets state but carries no properties.
        let mut data = vec![0x01u8, 0x00, 0x00, b'x'];
        data.extend_from_slice(&[0xA0, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            LzmaDecoder::new().decode_lzma2(&data, 1 << 16),
            Err(CompressError::InvalidFormat(_))
        ));
    }

    #[test]
    fn lzma2_rejects_invalid_control_byte() {
        // 0x01 = dictionary reset + one uncompressed byte; then 0x03
        // is neither a valid uncompressed chunk (0x01/0x02) nor an
        // LZMA chunk (>= 0x80).
        let data = [0x01u8, 0x00, 0x00, b'x', 0x03];
        assert!(matches!(
            LzmaDecoder::new().decode_lzma2(&data, 1 << 16),
            Err(CompressError::InvalidFormat(_))
        ));
    }

    #[test]
    fn decode_rejects_wrong_unpack_size() {
        // Encode 100 bytes but claim 50 in the size field.
        let input = vec![b'a'; 100];
        let mut compressed = LzmaEncoder::new().encode(&input);
        // Patch the 8-byte size field at offset 5.
        compressed[5..13].copy_from_slice(&50u64.to_le_bytes());
        assert!(LzmaDecoder::new().decode(&compressed).is_err());
    }
}
