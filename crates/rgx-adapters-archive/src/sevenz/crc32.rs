// SPDX-License-Identifier: Apache-2.0

//! CRC-32 (IEEE 802.3) over byte slices.
//!
//! Independent implementation from the published CRC definition: the
//! reflected polynomial 0xEDB88320, an initial register of all ones,
//! and a final complement. The lookup table is generated at compile
//! time from the polynomial itself — it is the definition, not a copied
//! table.
//!
//! # Throughput
//!
//! The original note here said per-member checksums in the 7z container
//! are small buffers, so a byte-at-a-time fold was the whole story. That
//! was wrong, and a fixture is what proved it: `sevenz_multifolder.7z`
//! is 24 KB on disk and declares **107 MB** across its two folders, so
//! the per-member CRC runs over 107 MB of payload — and the byte-at-a-time
//! fold is one table fetch and one shift per byte, which is where most
//! of the adapter's time went.
//!
//! So the fold is now **slice-by-8**: eight bytes fold into one table
//! pass. The recurrence is affine over GF(2), so a byte's contribution
//! `k` positions before the end is a fixed 32-bit value — one table per
//! distance. Eight bytes cost one XOR chain instead of eight shifts and
//! eight table fetches.
//!
//! The byte-at-a-time form is kept below as [`crc32_slow`] and is the
//! oracle the tests hold [`crc32`] against. They must agree at every
//! length; an optimisation that cannot pass that test is not an
//! optimisation.

/// The reflected IEEE 802.3 polynomial.
const POLY: u32 = 0xEDB8_8320;

/// The one-byte reflected table: `T0[i]` is the state after feeding byte `i`
/// into a zeroed state.
const fn t0() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { POLY ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

/// `T0`, the one-byte table.
static T0: [u32; 256] = t0();

/// Advance a single-byte contribution by `n` further zero bytes: feed `0`
/// into the state `n` times. `Tk[i]` is therefore the state reached by
/// feeding byte `i` and then `n` zeros from a zeroed state.
const fn advance(base: &[u32; 256], n: usize) -> [u32; 256] {
    let mut t = *base;
    let mut round = 0;
    while round < n {
        let mut i = 0;
        while i < 256 {
            // One zero byte: table[(s ^ 0) & 0xff] ^ (s >> 8).
            t[i] = T0[(t[i] & 0xff) as usize] ^ (t[i] >> 8);
            i += 1;
        }
        round += 1;
    }
    t
}

/// The eight tables: `Tk[i]` = byte `i` followed by `k` zero bytes.
static T: [[u32; 256]; 8] = [
    t0(),
    advance(&T0, 1),
    advance(&T0, 2),
    advance(&T0, 3),
    advance(&T0, 4),
    advance(&T0, 5),
    advance(&T0, 6),
    advance(&T0, 7),
];

/// CRC-32 checksum of `data`.
#[allow(missing_docs)]
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

/// Fold `data` into a running CRC register. `crc32` is
/// `crc32_update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF`; keep the same
/// convention when chaining calls.
#[inline]
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    let n = data.len();
    let full = n & !7;
    let mut i = 0;
    while i < full {
        // Reflected CRC: the first byte of the window is the *most*
        // significant position in the fold, so the table index descends
        // T7 -> T0 as the byte offset ascends. Eight bytes cost one XOR
        // chain instead of eight shifts and eight table fetches.
        crc = T[7][((crc ^ u32::from(data[i])) & 0xff) as usize]
            ^ T[6][(((crc >> 8) ^ u32::from(data[i + 1])) & 0xff) as usize]
            ^ T[5][(((crc >> 16) ^ u32::from(data[i + 2])) & 0xff) as usize]
            ^ T[4][(((crc >> 24) ^ u32::from(data[i + 3])) & 0xff) as usize]
            ^ T[3][data[i + 4] as usize]
            ^ T[2][data[i + 5] as usize]
            ^ T[1][data[i + 6] as usize]
            ^ T[0][data[i + 7] as usize];
        i += 8;
    }
    while i < n {
        crc = T0[((crc ^ u32::from(data[i])) & 0xff) as usize] ^ (crc >> 8);
        i += 1;
    }
    crc
}

/// The definition, unoptimised: one byte, one table fetch, one shift.
///
/// This is what [`crc32_update`] is checked against. It is not used on any
/// hot path; it exists so the slice-by-8 fold has an independent oracle in
/// the same file and cannot drift away from the CRC it claims to compute.
#[cfg(test)]
fn crc32_slow(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = T0[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Streaming form: feed chunks, then take the finished checksum.
#[derive(Debug, Clone, Default)]
pub struct Crc32Calculator {
    crc: u32,
}

impl Crc32Calculator {
    /// A calculator at the start of a stream.
    pub fn new() -> Self {
        Self { crc: 0xFFFF_FFFF }
    }

    /// Absorb the next chunk.
    pub fn update(&mut self, data: &[u8]) {
        self.crc = crc32_update(self.crc, data);
    }

    /// The checksum of everything absorbed so far.
    pub fn finish(self) -> u32 {
        self.crc ^ 0xFFFF_FFFF
    }

    /// Back to the start of a stream.
    pub fn reset(&mut self) {
        self.crc = 0xFFFF_FFFF;
    }

    /// The checksum so far, without consuming the calculator.
    pub fn current(&self) -> u32 {
        self.crc ^ 0xFFFF_FFFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_crc32_known() {
        // The standard check value: CRC-32 of "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc32_streaming() {
        let mut calc = Crc32Calculator::new();
        calc.update(b"123");
        calc.update(b"456");
        calc.update(b"789");
        assert_eq!(calc.finish(), 0xCBF43926);
    }

    #[test]
    fn test_crc32_update_consistency() {
        let full = crc32(b"Hello, World!");

        let mut partial = 0xFFFF_FFFF;
        partial = crc32_update(partial, b"Hello, ");
        partial = crc32_update(partial, b"World!");

        assert_eq!(partial ^ 0xFFFF_FFFF, full);
    }

    #[test]
    fn test_crc32_various_inputs() {
        assert_eq!(crc32(b"a"), 0xE8B7BE43);
        assert_eq!(crc32(b"ab"), 0x9E83486D);
        assert_eq!(crc32(b"abc"), 0x352441C2);
        assert_eq!(crc32(b"abcd"), 0xED82CD11);
    }

    /// The optimisation is only worth having if it is the same function.
    /// Hold the slice-by-8 fold against the byte-at-a-time definition at
    /// every length around the eight-byte window: seven is one tail byte,
    /// eight is one window, nine is one window and one byte.
    #[test]
    fn the_slice_by_8_fold_agrees_with_the_definition_at_every_length() {
        let mut data: Vec<u8> = Vec::new();
        for i in 0..64u32 {
            data.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        for len in 0..=data.len() {
            assert_eq!(
                crc32(&data[..len]),
                crc32_slow(&data[..len]),
                "length {len}"
            );
        }
    }

    /// The same agreement, for the streaming form: a chunked fold has to
    /// land where a single fold lands, because the 7z reader verifies a
    /// member's CRC over the bytes as they arrive.
    #[test]
    fn a_chunked_fold_lands_where_a_single_fold_lands() {
        let data: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        for split in 0..=data.len() {
            let mut state = 0xFFFF_FFFFu32;
            state = crc32_update(state, &data[..split]);
            state = crc32_update(state, &data[split..]);
            assert_eq!(state ^ 0xFFFF_FFFF, crc32_slow(&data), "split {split}");
        }
    }

    /// The calculator's own chunking has to agree with a single fold too.
    #[test]
    fn the_calculator_agrees_with_a_single_fold() {
        let data: Vec<u8> = (0..257u32).map(|i| (i % 253) as u8).collect();
        let mut calc = Crc32Calculator::new();
        for chunk in data.chunks(7) {
            calc.update(chunk);
        }
        assert_eq!(calc.finish(), crc32_slow(&data));
    }
}
