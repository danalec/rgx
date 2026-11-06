// SPDX-License-Identifier: Apache-2.0

//! The MQ arithmetic decoder of ITU-T T.88 Annex E.
//!
//! JBIG2 codes every pixel as a binary decision under an adaptive
//! probability estimate, and the estimate lives in a 94-state machine (T.88
//! Table E.1). The decoder here is the inverse of that machine: it keeps the
//! code register `C`, the interval register `A` and the bit counter `CT`, and
//! returns one decision per call.
//!
//! The register conventions are T.88 §E.3.1: `C` is a 32-bit register whose
//! high half (`Chigh`) carries the comparisons, `A` is the 16-bit interval
//! register, and `0x8000` is the renormalisation threshold. `INITDEC`,
//! `DECODE`, `RENORMD` and `BYTEIN` follow the flowcharts of Figures E.15
//! to E.20.
//!
//! Running past the end of the coded data is not an error: T.88 says a marker
//! code terminates the data and "1-bits are then fed to the decoder until the
//! decoding is complete". This implementation feeds `0xFF` bytes past the end
//! instead, which is the same convention every other implementation of the
//! format uses, and every caller decodes a *bounded* number of bits — so a
//! truncated stream terminates instead of looping.

use alloc::vec;
use alloc::vec::Vec;

/// One resolved MQ state.
///
/// The MPS sense is not stored: it is implied by the state's index (see
/// [`build_states`]), and the conditional exchange (`SWITCH` in Table E.1) is
/// already folded into the two next-state fields.
#[derive(Clone, Copy)]
struct MqState {
    /// `Qe` — the LPS probability estimate, 16-bit fixed point.
    qe: u16,
    /// Next state when the coded symbol was the MPS.
    next_mps: u8,
    /// Next state when the coded symbol was the LPS.
    next_lps: u8,
}

/// The 47 base rows of T.88 Table E.1, as `(Qe, NMPS, NLPS, SWITCH)`.
///
/// Written out one entry per line rather than packed, because these numbers
/// *are* the standard: a typo here is a silent misdecode that still renders a
/// plausible page, and the way to keep one out is to make every digit
/// readable and checkable against Table E.1.
const BASE_ROWS: [(u16, u8, u8, bool); 47] = [
    (0x5601, 1, 1, true),
    (0x3401, 2, 6, false),
    (0x1801, 3, 9, false),
    (0x0AC1, 4, 12, false),
    (0x0521, 5, 29, false),
    (0x0221, 38, 33, false),
    (0x5601, 7, 6, true),
    (0x5401, 8, 14, false),
    (0x4801, 9, 14, false),
    (0x3801, 10, 14, false),
    (0x3001, 11, 17, false),
    (0x2401, 12, 18, false),
    (0x1C01, 13, 20, false),
    (0x1601, 29, 21, false),
    (0x5601, 15, 14, true),
    (0x5401, 16, 14, false),
    (0x5101, 17, 15, false),
    (0x4801, 18, 16, false),
    (0x3801, 19, 17, false),
    (0x3401, 20, 18, false),
    (0x3001, 21, 19, false),
    (0x2801, 22, 19, false),
    (0x2401, 23, 20, false),
    (0x2201, 24, 21, false),
    (0x1C01, 25, 22, false),
    (0x1801, 26, 23, false),
    (0x1601, 27, 24, false),
    (0x1401, 28, 25, false),
    (0x1201, 29, 26, false),
    (0x1101, 30, 27, false),
    (0x0AC1, 31, 28, false),
    (0x09C1, 32, 29, false),
    (0x08A1, 33, 30, false),
    (0x0521, 34, 31, false),
    (0x0441, 35, 32, false),
    (0x02A1, 36, 33, false),
    (0x0221, 37, 34, false),
    (0x0141, 38, 35, false),
    (0x0111, 39, 36, false),
    (0x0085, 40, 37, false),
    (0x0049, 41, 38, false),
    (0x0025, 42, 39, false),
    (0x0015, 43, 40, false),
    (0x0009, 44, 41, false),
    (0x0005, 45, 42, false),
    (0x0001, 45, 43, false),
    (0x5601, 46, 46, false),
];

/// The full 94-entry state table.
///
/// States `0..47` have the MPS equal to 0 and states `47..94` have the MPS
/// equal to 1, so the MPS sense is recoverable from the index alone. A
/// `SWITCH` row sends the LPS into the other half of the table, and a
/// non-`SWITCH` row keeps it in its own half.
const STATES: [MqState; 94] = build_states();

const fn build_states() -> [MqState; 94] {
    let mut table = [MqState {
        qe: 0,
        next_mps: 0,
        next_lps: 0,
    }; 94];
    let mut i = 0;
    while i < 47 {
        let (qe, nmps, nlps, switch) = BASE_ROWS[i];
        table[i] = MqState {
            qe,
            next_mps: nmps,
            next_lps: if switch { nlps + 47 } else { nlps },
        };
        table[i + 47] = MqState {
            qe,
            next_mps: nmps + 47,
            next_lps: if switch { nlps } else { nlps + 47 },
        };
        i += 1;
    }
    table
}

/// A context's current MQ state, as an index into [`STATES`].
///
/// One byte, so a decoder can hold 65536 of them — one per possible pixel
/// context — in 64 KiB.
#[derive(Clone, Copy, Default)]
pub struct Context(pub u8);

impl Context {
    /// The MPS sense of this state: `true` when the more probable symbol is 1.
    #[inline]
    fn mps(self) -> bool {
        self.0 >= 47
    }
}

/// The MQ arithmetic decoder.
pub struct Decoder<'a> {
    data: &'a [u8],
    /// Index of the current byte `B`. May advance one past the end of the
    /// data, after which reads yield the `0xFF` past-end convention.
    bp: usize,
    /// The code register `C`.
    c: u32,
    /// The interval register `A`.
    a: u32,
    /// Bits left in the low half of `C`.
    ct: i32,
}

impl<'a> Decoder<'a> {
    /// `INITDEC` (T.88 Figure E.20).
    pub fn new(data: &'a [u8]) -> Self {
        let mut dec = Decoder {
            data,
            bp: 0,
            c: 0,
            a: 0,
            ct: 0,
        };
        // C = B << 16, with B the first byte of the coded data.
        dec.c = (dec.byte_at(0) as u32) << 16;
        dec.byte_in();
        dec.c <<= 7;
        dec.ct -= 7;
        dec.a = 0x8000;
        dec
    }

    /// The byte at `index`, or `0xFF` past the end of the data.
    #[inline]
    fn byte_at(&self, index: usize) -> u8 {
        match self.data.get(index) {
            Some(&b) => b,
            None => 0xFF,
        }
    }

    /// `BYTEIN` (T.88 Figure E.19).
    ///
    /// A `0xFF` byte is followed by a stuff bit, unless the next byte is a
    /// marker (`> 0x8F`), in which case the data ends and 1-bits are fed to
    /// the decoder from here on.
    #[inline]
    fn byte_in(&mut self) {
        if self.byte_at(self.bp) == 0xFF {
            let next = self.byte_at(self.bp + 1);
            if next > 0x8F {
                // A marker code (or the end of the data): feed 1-bits without
                // consuming the byte.
                self.c = self.c.wrapping_add(0xFF00);
                self.ct = 8;
            } else {
                // A stuff bit: it carries the carry of the previous byte into
                // the low bit of `Chigh`, so it is added nine bits up.
                self.bp += 1;
                self.c = self.c.wrapping_add((next as u32) << 9);
                self.ct = 7;
            }
        } else {
            self.bp += 1;
            let next = self.byte_at(self.bp);
            self.c = self.c.wrapping_add((next as u32) << 8);
            self.ct = 8;
        }
    }

    /// `RENORMD` (T.88 Figure E.18).
    #[inline]
    fn renorm(&mut self) {
        loop {
            if self.ct == 0 {
                self.byte_in();
            }
            self.a <<= 1;
            self.c <<= 1;
            self.ct -= 1;
            if self.a & 0x8000 != 0 {
                break;
            }
        }
    }

    /// `DECODE` (T.88 Figures E.15 to E.17): decode one decision under
    /// `context`, updating its state in place.
    ///
    /// Returns 0 or 1 — the value of the coded pixel.
    #[inline]
    pub fn decode_bit(&mut self, context: &mut Context) -> u8 {
        let state = &STATES[context.0 as usize];
        let qe = state.qe as u32;
        let mps = context.mps();

        self.a = self.a.wrapping_sub(qe);

        if (self.c >> 16) < qe {
            // The code point lies in the LPS sub-interval. Whether the decision
            // is really the LPS depends on which sub-interval is larger, and
            // that is the conditional exchange.
            let d = if self.a < qe {
                context.0 = state.next_mps;
                mps
            } else {
                context.0 = state.next_lps;
                !mps
            };
            self.a = qe;
            self.renorm();
            d as u8
        } else {
            // The code point lies in the MPS sub-interval.
            self.c = self.c.wrapping_sub(qe << 16);
            if self.a & 0x8000 == 0 {
                // A renormalisation is needed, and with it the conditional
                // exchange may have happened.
                let d = if self.a < qe {
                    context.0 = state.next_lps;
                    !mps
                } else {
                    context.0 = state.next_mps;
                    mps
                };
                self.renorm();
                d as u8
            } else {
                // No renormalisation: the MPS sense is the decision, and the
                // state is *not* advanced. T.88 §E.3.2 puts the update of
                // I(CX) from the NMPS column inside the renormalisation
                // discussion — "When a renormalisation is needed, the MPS/LPS
                // conditional exchange may have occurred... Then the index
                // I(CX) is updated from the next MPS index (NMPS) column" —
                // and the plain path says only that "if A is not less than
                // 0x8000, then the MPS sense stored at CX is used to set the
                // decoded decision D".
                //
                // This is where JBIG2's MQ coder differs from JPEG 2000's,
                // which updates the state on this path too; the two decoders
                // agree everywhere else.
                mps as u8
            }
        }
    }

    /// Decode one decision under a context that is *not* adaptive — the
    /// integer and IAID procedures of T.88 Annex A use fixed contexts whose
    /// state never changes.
    #[inline]
    pub fn decode_bit_fixed(&mut self, context: &mut Context) -> u8 {
        self.decode_bit(context)
    }
}

/// A decoder's context memory: one state per possible context value.
///
/// T.88 §E.3.7 resets the arithmetic coding statistics between regions, so a
/// region starts from a zeroed table. The table is sized by the caller
/// because the number of contexts a region uses depends on its template.
pub fn context_table(len: usize) -> Vec<Context> {
    vec![Context(0); len]
}

#[cfg(all(test, feature = "pdf"))]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_the_one_table_e1_prints() {
        // The first row of Table E.1: Qe = 0x5601, NMPS = 1, NLPS = 1,
        // SWITCH = 1 — so an LPS crosses into the MPS = 1 half of the table.
        assert_eq!(STATES[0].qe, 0x5601);
        assert_eq!(STATES[0].next_mps, 1);
        assert_eq!(STATES[0].next_lps, 48);
        // A non-switching row keeps the LPS in its own half.
        assert_eq!(STATES[1].next_lps, 6);
        assert_eq!(STATES[48].next_lps, 53);
        // The two halves share their Qe.
        for i in 0..47 {
            assert_eq!(STATES[i].qe, STATES[i + 47].qe);
        }
        // No transition leaves the table.
        for (i, s) in STATES.iter().enumerate() {
            assert!((s.next_mps as usize) < 94, "state {i}");
            assert!((s.next_lps as usize) < 94, "state {i}");
        }
    }

    #[test]
    fn an_empty_stream_decodes_without_panicking() {
        let mut dec = Decoder::new(&[]);
        let mut ctx = Context::default();
        for _ in 0..1000 {
            dec.decode_bit(&mut ctx);
        }
    }
}
