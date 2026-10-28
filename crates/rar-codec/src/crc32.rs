// SPDX-License-Identifier: Apache-2.0

//! CRC-32 (IEEE 802.3), the checksum RAR 5.0 places in every header and in
//! the file-data field.
//!
//! Independent reimplementation, written from the published CRC-32 definition
//! and from RARLAB's specification of what the checksum covers:
//!
//! > Header CRC32 — CRC32 of header data starting from Header size field and
//! > up to and including the optional extra area.
//!
//! Reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`, final XOR
//! `0xFFFFFFFF` — the same convention zip, gzip and PNG use.
//!
//! # Throughput
//!
//! A header checksum is a few dozen bytes, but `Archive::extract` verifies
//! the CRC of every extracted member, so the same routine runs over
//! multi-megabyte payloads. Two cuts matter there:
//!
//! - **slice-by-8.** Eight bytes fold into one table pass. The recurrence is
//!   affine over GF(2), so a byte's contribution `k` positions before the end
//!   is a fixed 32-bit value — one table per distance. Eight bytes cost one
//!   XOR chain instead of eight shifts and eight table fetches.
//! - **four-byte accumulators.** The eight tables are grouped so a step reads
//!   four `u32`s out of the tables and four straight out of the input; the
//!   hot loop is a handful of loads and XORs per 8 bytes.
//!
//! The byte-at-a-time form is kept below as [`crc32_slow`] and is the oracle
//! the tests hold [`crc32`] against. They must agree at every length; an
//! optimisation that cannot pass that test is not an optimisation.

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

/// CRC-32 of `data`, with the usual pre- and post-inversion.
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    update(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF
}

/// Continue a CRC over more bytes. `state` is the value *before* the final
/// XOR: pass `0xFFFF_FFFF` to start, and XOR with `0xFFFF_FFFF` only at the
/// end. This lets a header checksum be computed over a header that arrives
/// in pieces, and lets a running payload CRC be folded in.
#[inline]
pub fn update(mut state: u32, data: &[u8]) -> u32 {
    let n = data.len();
    let full = n & !7;
    let mut i = 0;
    while i < full {
        // Reflected CRC: the first byte of the window is the *most*
        // significant position in the fold, so the table index descends
        // T7 → T0 as the byte offset ascends. Eight bytes cost one XOR
        // chain instead of eight shifts and eight table fetches.
        state = T[7][((state ^ u32::from(data[i])) & 0xff) as usize]
            ^ T[6][(((state >> 8) ^ u32::from(data[i + 1])) & 0xff) as usize]
            ^ T[5][(((state >> 16) ^ u32::from(data[i + 2])) & 0xff) as usize]
            ^ T[4][(((state >> 24) ^ u32::from(data[i + 3])) & 0xff) as usize]
            ^ T[3][data[i + 4] as usize]
            ^ T[2][data[i + 5] as usize]
            ^ T[1][data[i + 6] as usize]
            ^ T[0][data[i + 7] as usize];
        i += 8;
    }
    while i < n {
        state = T0[((state ^ u32::from(data[i])) & 0xff) as usize] ^ (state >> 8);
        i += 1;
    }
    state
}

/// The definition, unoptimised: one byte, one table fetch, one shift.
///
/// This is what [`update`] is checked against. It is not used on any hot
/// path; it exists so the slice-by-8 fold has an independent oracle in the
/// same file and cannot drift away from the CRC it claims to compute.
#[cfg(test)]
fn crc32_slow(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = T0[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// The check value the CRC-32 definition fixes: CRC of "123456789".
    #[test]
    fn matches_the_widely_known_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn empty_input_is_the_post_inversion_of_all_ones() {
        assert_eq!(crc32(b""), 0);
    }

    /// The optimisation is only worth having if it is the same function.
    /// Hold `update` against the byte-at-a-time definition at every length,
    /// including every chunk boundary the 8-byte fold could get wrong.
    #[test]
    fn slice_by_eight_agrees_with_the_byte_at_a_time_definition() {
        // Deterministic pseudo-random input: no dependency on an RNG.
        let mut data = Vec::with_capacity(700);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..700 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data.push(x as u8);
        }
        for n in 0..=data.len() {
            assert_eq!(
                crc32(&data[..n]),
                crc32_slow(&data[..n]),
                "slice-by-8 disagrees at length {n}"
            );
        }
    }

    /// Chunking must not change the result: `update` is the incremental form
    /// of `crc32`, across every split point including the 8-byte boundaries.
    #[test]
    fn incremental_update_agrees_with_one_shot() {
        let data = b"Rar!\x1a\x07\x01\x00 header bytes and then a payload";
        let oneshot = crc32(data);
        for split in 0..=data.len() {
            let state = update(0xFFFF_FFFF, &data[..split]);
            let state = update(state, &data[split..]);
            assert_eq!(state ^ 0xFFFF_FFFF, oneshot, "split at {split}");
        }
    }

    /// A length that is not a multiple of 8 must take the tail path and
    /// still agree — the classic off-by-one in a slice-by-N fold.
    #[test]
    fn tails_of_every_length_take_the_byte_path_and_agree() {
        let base = b"payload bytes that are deliberately not a multiple of eight";
        for n in 0..=base.len() {
            assert_eq!(crc32(&base[..n]), crc32_slow(&base[..n]));
        }
    }

    /// Flipping any single bit changes the checksum: a real error detector.
    #[test]
    fn a_single_bit_flip_changes_the_checksum() {
        let mut data = b"header-size-and-extra-area".to_vec();
        let base = crc32(&data);
        for i in 0..data.len() {
            for bit in 0..8 {
                data[i] ^= 1 << bit;
                assert_ne!(crc32(&data), base, "byte {i} bit {bit} went unnoticed");
                data[i] ^= 1 << bit;
            }
        }
    }

    /// Large input takes the 8-byte fold almost exclusively; make sure the
    /// optimisation is what is actually running there and still correct.
    #[test]
    fn a_large_payload_agrees_at_every_eight_byte_boundary() {
        let mut data = Vec::with_capacity(4096);
        for i in 0..4096u32 {
            data.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        assert_eq!(crc32(&data), crc32_slow(&data));
        for n in (0..=4096).step_by(8) {
            assert_eq!(crc32(&data[..n]), crc32_slow(&data[..n]));
        }
    }
}
