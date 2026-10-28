// SPDX-License-Identifier: Apache-2.0

//! CRC-64/XZ, the check type `0x04` of the .xz container format.
//!
//! Independent reimplementation of the published CRC parameters, written
//! from the polynomial and the bit-at-a-time recurrence rather than from
//! any implementation's source. The register starts all-ones, bits are
//! mixed least-significant-first, and the result is complemented — which
//! is what distinguishes this variant from its neighbours.
//!
//! | parameter | value                           |
//! |-----------|---------------------------------|
//! | width     | 64                              |
//! | poly      | `0x42F0E1EBA9EA3693` (ECMA-182) |
//! | init      | `0xFFFFFFFFFFFFFFFF`            |
//! | refin     | true (LSB-first)                |
//! | refout    | true                            |
//! | xorout    | `0xFFFFFFFFFFFFFFFF`            |
//!
//! `check("123456789") = 0x995DC9BBDF1939FA`
//!
//! Two neighbours this must not drift into: CRC-64/ECMA-182 proper
//! (`init = 0`, MSB-first, `xorout = 0`, check `0x6C40DF5F0B497347`), and
//! the unnamed CRC you get by feeding the un-reflected polynomial to an
//! LSB-first loop (check `0xB86883E6FA710A9F`). The loop below works on
//! the reflected form `0xC96C5795D7870F42`, derived here from the normal
//! form rather than typed in.

/// The ECMA-182 polynomial in its normal (MSB-first) form.
const ECMA_182: u64 = 0x42F0_E1EB_A9EA_3693;

/// Reflected forms are what an LSB-first recurrence steps against.
const fn reflect64(value: u64) -> u64 {
    let mut out = 0u64;
    let mut i = 0;
    while i < 64 {
        out = (out << 1) | ((value >> i) & 1);
        i += 1;
    }
    out
}

/// ECMA-182 as the recurrence below consumes it.
const POLY: u64 = reflect64(ECMA_182);

// The one bug this module has had is the un-reflected polynomial here;
// pinning the expected value keeps a future edit honest.
const _: () = assert!(POLY == 0xC96C_5795_D787_0F42);

/// The register before any input, and its complement after.
const INIT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// `STEP[k]` absorbs byte `k` of an 8-byte little-endian step: the
/// one-byte recurrence folded `k` more zero bytes deep. Eight input bytes
/// then cost eight independent lookups and seven XORs instead of eight
/// dependent lookup-shift rounds.
const STEP: [[u64; 256]; 8] = build_step();

const fn build_step() -> [[u64; 256]; 8] {
    let mut step = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        step[0][i] = crc;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = step[k - 1][i];
            step[k][i] = (prev >> 8) ^ step[0][(prev & 0xFF) as usize];
            i += 1;
        }
        k += 1;
    }
    step
}

/// Calculate the CRC-64/XZ of `data` (check type `0x04`).
///
/// # Example
///
/// ```
/// # use rgx_core::compress::xz::crc64::crc64;
/// assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
/// ```
#[must_use]
pub fn crc64(data: &[u8]) -> u64 {
    let mut crc = INIT;
    let mut buf = data;
    while buf.len() >= 8 {
        let block = u64::from_le_bytes(buf[..8].try_into().unwrap());
        buf = &buf[8..];
        // Little-endian XOR puts byte 0 of the block in the low byte of
        // the register. Byte 0 still has seven zero-byte folds pending,
        // so it indexes STEP[7]; byte 7 is already fully folded and takes
        // STEP[0].
        crc ^= block;
        crc = fold8(crc);
    }
    for &b in buf {
        crc = (crc >> 8) ^ STEP[0][(crc as u8 ^ b) as usize];
    }
    !crc
}

/// Fold all eight bytes of a just-XORed little-endian word through the
/// eight tables, no two lookups dependent on each other.
fn fold8(mix: u64) -> u64 {
    STEP[7][(mix & 0xFF) as usize]
        ^ STEP[6][((mix >> 8) & 0xFF) as usize]
        ^ STEP[5][((mix >> 16) & 0xFF) as usize]
        ^ STEP[4][((mix >> 24) & 0xFF) as usize]
        ^ STEP[3][((mix >> 32) & 0xFF) as usize]
        ^ STEP[2][((mix >> 40) & 0xFF) as usize]
        ^ STEP[1][((mix >> 48) & 0xFF) as usize]
        ^ STEP[0][((mix >> 56) & 0xFF) as usize]
}

#[cfg(all(test, feature = "xz"))]
mod tests {
    use alloc::vec::Vec;

    use super::{crc64, POLY};

    /// Bit-at-a-time CRC-64/XZ, transcribed straight from the parameter model
    /// above, to cross-check the table-driven path.
    fn reference(data: &[u8]) -> u64 {
        let mut crc = 0xFFFF_FFFF_FFFF_FFFFu64;
        for &b in data {
            crc ^= u64::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ POLY
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn catalogue_check_value() {
        // CRC-64/XZ check value for the ASCII string "123456789".
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn empty_input() {
        assert_eq!(crc64(b""), 0);
    }

    #[test]
    fn not_crc64_ecma182() {
        // CRC-64/ECMA-182 (init 0, MSB-first, xorout 0) is a different variant
        // of the same polynomial family and must not agree.
        assert_ne!(crc64(b"123456789"), 0x6C40_DF5F_0B49_7347);
    }

    #[test]
    fn not_the_bit_reversed_polynomial() {
        // The previous bug: the un-reflected ECMA-182 polynomial in an
        // LSB-first loop. Pinned so it cannot come back silently.
        assert_ne!(crc64(b"123456789"), 0xB868_83E6_FA71_0A9F);
    }

    #[test]
    fn matches_bitwise_reference() {
        let mut data = Vec::new();
        let mut x: u32 = 0x1234_5678;
        for _ in 0..4096 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            data.push((x >> 16) as u8);
        }
        for len in [0, 1, 2, 7, 8, 9, 63, 64, 65, 255, 256, 257, 1000] {
            assert_eq!(crc64(&data[..len]), reference(&data[..len]), "len {len}");
        }
    }

    #[test]
    fn matches_real_xz_block_check() {
        // A real .xz stream written by liblzma with check type CRC64
        // (`xz --check=crc64`). Stream Flags say 0x04, and the 8 bytes at
        // offset 84 are the Block Check for the 105-byte plaintext below,
        // stored little-endian per the .xz format.
        const STREAM: &[u8] = &[
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x33, 0x69, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x35, 0x84, 0x8d, 0x8a, 0xe0, 0x00, 0x68, 0x00, 0x2b, 0x5d, 0x00, 0x39, 0x19, 0xcb,
            0x72, 0x22, 0x16, 0x16, 0x6f, 0x95, 0x09, 0x3a, 0xa4, 0x23, 0x3f, 0xd1, 0xc4, 0x76,
            0xa3, 0xeb, 0xf1, 0xae, 0x6f, 0x3b, 0x92, 0xdd, 0xae, 0xc0, 0x63, 0x06, 0x2d, 0x9e,
            0x8a, 0x1b, 0x00, 0xec, 0x40, 0x59, 0x3a, 0xf1, 0x19, 0x18, 0x00, 0x00, 0x00, 0x00,
            0x8f, 0x61, 0x92, 0x10, 0x0f, 0x2a, 0xad, 0xbf, 0x00, 0x01, 0x4f, 0x69, 0x1d, 0x3f,
            0x09, 0x63, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
        ];
        const PLAINTEXT: &[u8] = b"rgx xz CRC-64 known-answer vector.\n\
                                    rgx xz CRC-64 known-answer vector.\n\
                                    rgx xz CRC-64 known-answer vector.\n";

        assert_eq!(&STREAM[..6], b"\xfd7zXZ\x00", "stream magic");
        assert_eq!(STREAM[7], 0x04, "check type is CRC-64");

        let stored = u64::from_le_bytes(STREAM[84..92].try_into().unwrap());
        assert_eq!(crc64(PLAINTEXT), stored);
        assert_eq!(stored, 0xBFAD_2A0F_1092_618F);
    }

    /// A checksum that panics on arbitrary bytes is a crash every
    /// corrupted file can trigger; Err is fine, panic is not.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&str, Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("check", b"123456789".to_vec()),
            ("long", alloc::vec![0x5A; 4096]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "crc64", |data| {
            let _ = crc64(data);
        });
    }
}
