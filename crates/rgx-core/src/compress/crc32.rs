// SPDX-License-Identifier: Apache-2.0

//! CRC-32 as IEEE 802.3 specifies it: the checksum ZIP, gzip and PNG carry.
//!
//! Independent reimplementation of the published CRC, written from the
//! polynomial and the bit-at-a-time recurrence rather than from any
//! implementation's source. The register starts all-ones, each input bit
//! is mixed in least-significant-first against the reflected polynomial
//! `0x04C11DB7` (held here as `0xEDB88320`), and the result is
//! complemented. Everything below is that recurrence: the table is it
//! evaluated for one byte, and the wide loops fold more bytes per step
//! around it.

/// The reflected polynomial `x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+
/// x^8+x^7+x^5+x^4+x^2+x+1`. Its low bit is set, so every step of the
/// recurrence either shifts right or shifts right and folds this in.
const POLY: u32 = 0xEDB8_8320;

/// The register value before any input, and its complement after.
const INIT: u32 = 0xFFFF_FFFF;

/// `STEP[k]` absorbs byte `k` of an 8-byte little-endian step: it is the
/// one-byte table folded `k` more zero bytes deep. Eight input bytes then
/// cost eight independent lookups and seven XORs instead of eight
/// dependent lookup-shift rounds — the dependency chain is what a
/// byte-at-a-time CRC spends its time on, because every byte would
/// otherwise wait for the previous register.
const STEP: [[u32; 256]; 8] = build_step();

const fn build_step() -> [[u32; 256]; 8] {
    let mut step = [[0u32; 256]; 8];
    // Table 0: the recurrence itself, one byte in, one register update out.
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
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
    // Tables 1..8: fold one more zero byte into the previous table.
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

/// CRC-32 checksum of data.
///
/// # Example
///
/// ```
/// # use rgx_core::compress::crc32::crc32;
/// let data = b"123456789";
/// assert_eq!(crc32(data), 0xCBF43926);
/// ```
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(INIT, data) ^ INIT
}

/// Update CRC-32 with additional data.
///
/// Use this for streaming CRC calculation. `crc` is the register as the
/// previous call left it: start from `0xFFFFFFFF`, then complement the
/// final register to publish.
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    let mut buf = data;
    // Two independent 8-byte chains per 16 bytes. They share no register,
    // so the CPU retires one while the other is in flight and the
    // dependent-chain latency does not serialise the loop. Both chains use
    // the same table set; each absorbs its own eight bytes.
    while buf.len() >= 16 {
        let a = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let b = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let c = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let d = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        buf = &buf[16..];
        let first = fold8(crc ^ a, b);
        crc = fold8(first ^ c, d);
    }
    while buf.len() >= 8 {
        let a = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let b = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        buf = &buf[8..];
        crc = fold8(crc ^ a, b);
    }
    for &byte in buf {
        let index = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ STEP[0][index];
    }
    crc
}

/// Fold one little-endian word pair `(lo, hi)` into the register: eight
/// bytes absorbed through the eight tables with no two lookups dependent
/// on each other.
fn fold8(lo_mix: u32, hi: u32) -> u32 {
    STEP[7][(lo_mix & 0xFF) as usize]
        ^ STEP[6][((lo_mix >> 8) & 0xFF) as usize]
        ^ STEP[5][((lo_mix >> 16) & 0xFF) as usize]
        ^ STEP[4][((lo_mix >> 24) & 0xFF) as usize]
        ^ STEP[3][(hi & 0xFF) as usize]
        ^ STEP[2][((hi >> 8) & 0xFF) as usize]
        ^ STEP[1][((hi >> 16) & 0xFF) as usize]
        ^ STEP[0][((hi >> 24) & 0xFF) as usize]
}

/// CRC-32 calculator for streaming operations.
#[derive(Debug, Clone, Default)]
pub struct Crc32Calculator {
    crc: u32,
}

impl Crc32Calculator {
    /// Create a new CRC-32 calculator.
    pub fn new() -> Self {
        Self { crc: INIT }
    }

    /// Update with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.crc = crc32_update(self.crc, data);
    }

    /// Get the final CRC-32 value.
    pub fn finish(self) -> u32 {
        self.crc ^ INIT
    }

    /// Reset the calculator.
    pub fn reset(&mut self) {
        self.crc = INIT;
    }

    /// Get current CRC value without finalizing.
    pub fn current(&self) -> u32 {
        self.crc ^ INIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn test_crc32_known() {
        // Test vector from PNG spec
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

        let mut partial = 0xFFFFFFFF;
        partial = crc32_update(partial, b"Hello, ");
        partial = crc32_update(partial, b"World!");

        assert_eq!(partial ^ 0xFFFFFFFF, full);
    }

    #[test]
    fn test_crc32_various_inputs() {
        assert_eq!(crc32(b"a"), 0xE8B7BE43);
        assert_eq!(crc32(b"ab"), 0x9E83486D);
        assert_eq!(crc32(b"abc"), 0x352441C2);
        assert_eq!(crc32(b"abcd"), 0xED82CD11);
    }

    /// Slice-by-8 only reads eight bytes at a time, so every length around a
    /// word boundary is a place it can be wrong, and a wrong CRC here is a
    /// corrupt pack that verifies. Seven is all tail; eight is one whole
    /// slice; nine is one slice and one byte.
    #[test]
    fn test_crc32_around_the_slice_boundary() {
        assert_eq!(crc32(&[b'c'; 7]), 0x8EA9DC7D);
        assert_eq!(crc32(&[b'd'; 8]), 0x01798D55);
        assert_eq!(crc32(&[b'd'; 9]), 0x83DD963A);
        assert_eq!(crc32(&[b'a'; 1000]), 0x9A38DA03);
        assert_eq!(crc32(&[b'b'; 4096]), 0x41A6F66B);
        let mut pangram = alloc::vec::Vec::new();
        for _ in 0..40 {
            pangram.extend_from_slice(b"The quick brown fox jumps over the lazy dog. ");
        }
        assert_eq!(crc32(&pangram), 0x6495C3E6);
    }

    /// Splitting a buffer anywhere must give the same answer as not splitting
    /// it. A pack reader depends on this when it hashes a record and then
    /// the rest of the payload.
    #[test]
    fn test_crc32_splits_anywhere() {
        let data: alloc::vec::Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(31) >> 3) as u8)
            .collect();
        let full = crc32(&data);
        for split in [1usize, 7, 8, 9, 15, 16, 63, 64, 511, 512, 999] {
            let mut c = 0xFFFF_FFFF;
            c = crc32_update(c, &data[..split]);
            c = crc32_update(c, &data[split..]);
            assert_eq!(c ^ 0xFFFF_FFFF, full, "split at {split}");
        }
    }

    /// The bit-at-a-time recurrence the specification states, computed
    /// without any table. The table and the wide folds must agree with it
    /// on every input, not just on the published check value: a table
    /// built wrong fails here for every length whose bytes hit the bad
    /// entry, while "123456789" alone can hide that.
    #[test]
    fn the_tables_agree_with_the_spec_recurrence() {
        fn spec_crc(data: &[u8]) -> u32 {
            let mut crc = INIT;
            for &byte in data {
                crc ^= byte as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ POLY
                    } else {
                        crc >> 1
                    };
                }
            }
            crc ^ INIT
        }
        let shapes: [&[u8]; 6] = [
            b"",
            b"a",
            b"123456789",
            &[0xFF; 17],
            &[0x00, 0xFF, 0x00, 0xFF, 0x55, 0xAA],
            b"The quick brown fox jumps over the lazy dog",
        ];
        for shape in shapes {
            assert_eq!(crc32(shape), spec_crc(shape), "len {}", shape.len());
        }
    }

    /// A checksum that panics on arbitrary bytes is a crash every
    /// corrupted file can trigger; Err is fine, panic is not.
    #[cfg(feature = "std")]
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: alloc::vec::Vec<(&str, alloc::vec::Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("check", b"123456789".to_vec()),
            ("long", alloc::vec![0xA5; 5000]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "crc32", |data| {
            let _ = crc32(data);
            let mut calc = Crc32Calculator::new();
            if data.len() > 3 {
                calc.update(&data[..3]);
                calc.update(&data[3..]);
                let _ = calc.finish();
            }
        });
    }
}
