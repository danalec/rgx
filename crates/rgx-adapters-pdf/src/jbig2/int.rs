// SPDX-License-Identifier: Apache-2.0

//! The arithmetic integer decoding procedures of ITU-T T.88 Annex A.
//!
//! A JBIG2 stream codes integers — a strip's T offset, a symbol's width, a
//! symbol ID — with the same MQ arithmetic coder the pixels use, but with a
//! decision tree of its own (T.88 Table A.1). Every procedure keeps its own
//! bank of 512 adaptive probability estimates, because the context is
//! "IAx" followed by the nine bits of the procedure's own history register
//! `PREV`.
//!
//! IAID is the odd one out: it codes a symbol ID as a fixed number of bits
//! walking a binary tree, so its context is the tree node itself.

use alloc::vec::Vec;

use super::mq::{Context, Decoder};

/// The number of contexts each integer procedure keeps (T.88 §A.2: a
/// nine-bit `PREV`).
pub const CONTEXTS_PER_PROC: usize = 512;

/// The arithmetic integer decoding procedures of T.88 §A.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IntProc {
    /// The number of symbol instances in an aggregation.
    Iaai,
    /// The difference in height between two height classes.
    Iadh,
    /// The S coordinate of the second and subsequent symbol instances.
    Iads,
    /// The T coordinate of the second and subsequent symbol instances.
    Iadt,
    /// The difference in width between two symbols in a height class.
    Iadw,
    /// The export flags.
    Iaex,
    /// The S coordinate of the first symbol instance in a strip.
    Iafs,
    /// The T coordinate of the symbol instances in a strip.
    Iait,
    /// The delta height of symbol instance refinements.
    Iardh,
    /// The delta width of symbol instance refinements.
    Iardw,
    /// The delta X position of symbol instance refinements.
    Iardx,
    /// The delta Y position of symbol instance refinements.
    Iardy,
    /// The refinement indicator of symbol instances.
    Iari,
}

impl IntProc {
    /// The procedure's index, which selects its context bank.
    fn index(self) -> usize {
        match self {
            IntProc::Iaai => 0,
            IntProc::Iadh => 1,
            IntProc::Iads => 2,
            IntProc::Iadt => 3,
            IntProc::Iadw => 4,
            IntProc::Iaex => 5,
            IntProc::Iafs => 6,
            IntProc::Iait => 7,
            IntProc::Iardh => 8,
            IntProc::Iardw => 9,
            IntProc::Iardx => 10,
            IntProc::Iardy => 11,
            IntProc::Iari => 12,
        }
    }
}

/// The value an integer procedure produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decoded {
    /// A finite value.
    Value(i64),
    /// The out-of-band marker (T.88 Table A.1).
    Oob,
}

/// The context banks of the arithmetic integer decoding procedures.
pub struct IntegerContexts {
    banks: [[Context; CONTEXTS_PER_PROC]; 13],
}

impl Default for IntegerContexts {
    fn default() -> Self {
        Self {
            banks: [[Context(0); CONTEXTS_PER_PROC]; 13],
        }
    }
}

impl IntegerContexts {
    /// Zero every procedure's bank (T.88 resets the coder between segments).
    pub fn reset(&mut self) {
        for bank in self.banks.iter_mut() {
            for c in bank.iter_mut() {
                *c = Context(0);
            }
        }
    }

    /// Decode one integer under `proc`.
    ///
    /// The decision tree is T.88 Table A.1: a sign bit, then a run of ones
    /// selecting the magnitude's range, then the magnitude's bits. A sign bit
    /// of one with a zero magnitude is the out-of-band marker.
    pub fn decode(&mut self, dec: &mut Decoder<'_>, proc: IntProc) -> Decoded {
        let bank = &mut self.banks[proc.index()];
        let mut prev: u16 = 1;

        // Decode one bit under the context named by the nine bits of `PREV`,
        // then advance `PREV` (T.88 §A.2 step 3).
        macro_rules! bit {
            () => {{
                let b = dec.decode_bit(&mut bank[(prev & 0x1FF) as usize]) != 0;
                prev = if prev < 0x100 {
                    (prev << 1) | (b as u16)
                } else {
                    (((prev << 1) | (b as u16)) & 0x1FF) | 0x100
                };
                b
            }};
        }

        let sign = bit!();
        // The magnitude's range: the number of value bits and their offset.
        let (n_bits, offset): (u32, i64) = if !bit!() {
            (2, 0)
        } else if !bit!() {
            (4, 4)
        } else if !bit!() {
            (6, 20)
        } else if !bit!() {
            (8, 84)
        } else if !bit!() {
            (12, 340)
        } else {
            (32, 4436)
        };

        let mut value: u64 = 0;
        for _ in 0..n_bits {
            value = (value << 1) | bit!() as u64;
        }
        let magnitude = offset + value as i64;
        if sign {
            if magnitude == 0 {
                Decoded::Oob
            } else {
                Decoded::Value(-magnitude)
            }
        } else {
            Decoded::Value(magnitude)
        }
    }
}

/// The IAID symbol ID procedure (T.88 §A.3).
///
/// The ID is `SBSYMCODELEN` bits read most significant first, walking a
/// binary tree whose node index is the value decoded so far with an implicit
/// leading one. The tree has `2^SBSYMCODELEN` nodes, and each node is a
/// context of its own.
#[derive(Default)]
pub struct IaidContexts {
    states: Vec<Context>,
}

impl IaidContexts {
    /// Size and zero the tree for a `bits`-wide symbol ID.
    pub fn reset_for_bits(&mut self, bits: u8) {
        let needed = 1usize << bits;
        if self.states.len() < needed {
            self.states.resize(needed, Context(0));
        }
        for c in self.states[..needed].iter_mut() {
            *c = Context(0);
        }
    }

    /// Decode a `bits`-wide symbol ID.
    pub fn decode(&mut self, dec: &mut Decoder<'_>, bits: u8) -> u32 {
        if bits == 0 {
            return 0;
        }
        let len = self.states.len();
        if len == 0 {
            return 0;
        }
        let mut prev: usize = 1;
        for _ in 0..bits {
            let index = if prev < len { prev } else { len - 1 };
            let b = dec.decode_bit(&mut self.states[index]);
            prev = (prev << 1) | (b as usize);
        }
        (prev - (1usize << bits)) as u32
    }
}

/// The number of bits an IAID-coded symbol ID needs for `count` symbols.
pub fn code_length(count: usize) -> u8 {
    let mut bits = 0u8;
    while (1usize << bits) < count {
        bits += 1;
    }
    bits
}

#[cfg(all(test, feature = "pdf"))]
mod tests {
    use super::*;

    #[test]
    fn the_code_length_covers_the_symbol_space() {
        assert_eq!(code_length(1), 0);
        assert_eq!(code_length(2), 1);
        assert_eq!(code_length(3), 2);
        assert_eq!(code_length(4), 2);
        assert_eq!(code_length(42), 6);
        assert_eq!(code_length(64), 6);
        assert_eq!(code_length(65), 7);
    }
}
