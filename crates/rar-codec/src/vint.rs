// SPDX-License-Identifier: Apache-2.0

//! Variable-length integers, exactly as RAR 5.0 defines them.
//!
//! Independent reimplementation, written from RARLAB's published RAR 5.0
//! archive format specification:
//!
//! > Variable length integer. Can include one or more bytes, where lower 7
//! > bits of every byte contain integer data and highest bit in every byte is
//! > the continuation flag. If highest bit is 0, this is the last byte in
//! > sequence. So first byte contains 7 least significant bits of integer and
//! > continuation flag. Second byte, if present, contains next 7 bits and so
//! > on. Currently RAR format uses vint to store up to 64 bit integers,
//! > resulting in 10 bytes maximum.
//!
//! # Throughput
//!
//! A header walks field by field and almost every field is a vint, so this
//! runs dozens of times per member and never over a long stream. The cost is
//! not the arithmetic, it is the per-call slicing and the loop setup. Two
//! cuts:
//!
//! - **no re-slicing.** [`read_r`] indexes the caller's buffer directly with
//!   one bounds check at the cursor, instead of taking `&data[cursor..]`
//!   first. That removes a range check per field.
//! - **a one-byte fast path.** Values below 0x80 are one byte with no
//!   continuation flag, and that is the overwhelmingly common shape (flags,
//!   types, counts). It returns before any loop is entered.
//!
//! The tail of a multi-byte value is rare enough that it does not unroll.

use alloc::vec::Vec;

use crate::{Error, Result};

/// Maximum bytes a RAR vint occupies: ceil(64 / 7).
pub const MAX_LEN: usize = 10;

/// Decode one vint at `data[0..]`.
///
/// Returns `(value, bytes_consumed)`. Fails with [`Error::Truncated`] if the
/// buffer ends mid-sequence, [`Error::Malformed`] if the value does not fit
/// in 64 bits (more than 10 bytes, or the 10th byte carrying bits that would
/// exceed `u64`).
#[inline]
pub fn read(data: &[u8]) -> Result<(u64, usize)> {
    let first = *data.first().ok_or(Error::Truncated)?;
    // Fast path: no continuation flag means the value is that one byte.
    if first & 0x80 == 0 {
        return Ok((u64::from(first), 1));
    }
    read_multibyte(data, 0, first)
}

/// Decode one vint at `data[*cursor..]`, advancing the cursor past it.
///
/// This is the form a sequential header parser wants: walk a structure
/// field by field without re-slicing. Semantics are identical to [`read`].
#[inline]
pub fn read_r(data: &[u8], cursor: &mut usize) -> Result<u64> {
    let start = *cursor;
    let first = *data.get(start).ok_or(Error::Truncated)?;
    let (v, used) = if first & 0x80 == 0 {
        // One bounds check above, one add below; nothing else touches data.
        (u64::from(first), 1)
    } else {
        // Only the rare multi-byte shape pays for the offset walk below.
        read_multibyte(data, start, first)?
    };
    *cursor = start + used;
    Ok(v)
}

/// The uncommon half: a value whose first byte carried the continuation
/// flag. `first` is `data[start]`, already known to have bit 7 set. `start`
/// is the offset of the vint inside `data` — the cursor form cannot re-slice
/// without a range check, so the offset travels with the call instead.
fn read_multibyte(data: &[u8], start: usize, first: u8) -> Result<(u64, usize)> {
    let mut value = u64::from(first & 0x7f);
    let mut shift = 7u32;
    for i in 1..MAX_LEN {
        let b = *data.get(start + i).ok_or(Error::Truncated)?;
        // A payload bit past 63 would be shifted out; refuse rather than
        // silently truncate the caller's length field.
        let payload = u64::from(b & 0x7f);
        if shift == 63 && payload > 1 {
            return Err(Error::Malformed("vint exceeds 64 bits"));
        }
        value |= payload << shift;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    // The 10th byte still had its continuation flag set.
    Err(Error::Malformed("vint longer than 10 bytes"))
}

/// Bytes `v` occupies when encoded. Always in `1..=10`.
#[inline]
pub fn len(v: u64) -> usize {
    match v {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        0x4000..=0x1f_ffff => 3,
        0x20_0000..=0xfff_ffff => 4,
        0x1000_0000..=0x7_ffff_ffff => 5,
        0x8_0000_0000..=0x3ff_ffff_ffff => 6,
        0x400_0000_0000..=0x1_ffff_ffff_ffff => 7,
        0x2_0000_0000_0000..=0xff_ffff_ffff_ffff => 8,
        0x100_0000_0000_0000..=0x7fff_ffff_ffff_ffff => 9,
        _ => 10,
    }
}

/// Append `v` to `out` in RAR vint form.
///
/// The format also admits a pre-allocated, over-padded form (leading `0x80`
/// bytes meaning "0 with continuation"). This writer always emits the
/// shortest form; readers accept both.
#[inline]
pub fn write(out: &mut Vec<u8>, v: u64) {
    // Reserve first: the caller is usually writing a run of fields into one
    // buffer, and `len` already knows the answer.
    out.reserve(len(v));
    // The common one-byte case avoids the loop entirely.
    if v < 0x80 {
        out.push(v as u8);
        return;
    }
    let mut rest = v;
    while rest >= 0x80 {
        out.push(((rest & 0x7f) as u8) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// The byte-at-a-time ladder in the spec, round-tripped at every width.
    #[test]
    fn round_trips_at_every_byte_width() {
        for width in 1..=10u32 {
            // A value whose shortest form is exactly `width` bytes:
            // 0x7f, 0x3fff, 0x1fffff, ... i.e. (1 << (7*width)) - 1.
            let v = if width == 10 {
                u64::MAX
            } else {
                (1u64 << (7 * width)) - 1
            };
            assert_eq!(len(v), width as usize, "len disagrees at width {width}");
            let mut buf = Vec::new();
            write(&mut buf, v);
            assert_eq!(
                buf.len(),
                width as usize,
                "encode disagrees at width {width}"
            );
            let (got, used) = read(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(used, width as usize);
        }
    }

    /// Every continuation byte carries the flag; the last does not.
    #[test]
    fn continuation_flag_is_set_except_on_the_last_byte() {
        let mut buf = Vec::new();
        write(&mut buf, 0x3fff); // two bytes
        assert_eq!(buf.len(), 2);
        assert_ne!(buf[0] & 0x80, 0);
        assert_eq!(buf[1] & 0x80, 0);
    }

    /// The spec's over-provisioned form: leading `0x80` means "0 with
    /// continuation", so a padded encoding of 0 decodes to 0.
    #[test]
    fn a_padded_zero_decodes_to_zero() {
        let (v, used) = read(&[0x80, 0x80, 0x00]).unwrap();
        assert_eq!((v, used), (0, 3));
    }

    #[test]
    fn a_buffer_ending_mid_sequence_is_truncated() {
        assert_eq!(read(&[0x80]), Err(Error::Truncated));
        assert_eq!(read(&[0x80, 0x80]), Err(Error::Truncated));
        assert_eq!(read(&[]), Err(Error::Truncated));
    }

    /// An 11th continuation byte is malformed, not a silently wrapped value.
    #[test]
    fn eleven_bytes_is_malformed() {
        let mut buf = vec![0x80u8; 11];
        buf.push(0x00);
        assert!(matches!(read(&buf), Err(Error::Malformed(_))));
    }

    /// A tenth byte whose payload would need bit 63 and more is malformed.
    #[test]
    fn a_tenth_byte_carrying_bits_past_63_is_malformed() {
        // 9 continuation bytes, then a 10th with payload 0x02: bit 63 set
        // plus bit 64, which u64 cannot hold.
        let mut buf = vec![0x80u8; 9];
        buf.push(0x02);
        assert!(matches!(read(&buf), Err(Error::Malformed(_))));
    }

    /// `len` and `write` agree at boundaries, not just at round-trip points.
    #[test]
    fn len_matches_the_encoded_form_at_boundaries() {
        for v in [
            0,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            0x1f_ffff,
            0x20_0000,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write(&mut buf, v);
            assert_eq!(len(v), buf.len(), "len disagrees for {v:#x}");
        }
    }

    /// `read_r` is the same decoder as `read`, just cursor-shaped. The fast
    /// path and the multi-byte path must both agree with it.
    #[test]
    fn read_r_agrees_with_read_at_every_width() {
        for v in [0u64, 1, 0x7f, 0x80, 0x3fff, 0x1f_ffff, u64::MAX] {
            let mut buf = Vec::new();
            write(&mut buf, v);
            // Pad the front so the cursor has to be honoured, and the back
            // so an over-read would be visible as a wrong consumed length.
            let mut framed = vec![0x11u8; 4];
            framed.extend_from_slice(&buf);
            framed.extend_from_slice(&[0x22; 4]);
            let mut cursor = 4;
            let got = read_r(&framed, &mut cursor).unwrap();
            assert_eq!(got, v);
            assert_eq!(cursor, 4 + buf.len());
        }
    }

    /// A cursor already past the end truncates instead of panicking.
    #[test]
    fn read_r_past_the_end_is_truncated() {
        let mut cursor = 3;
        assert_eq!(read_r(&[0x01, 0x02], &mut cursor), Err(Error::Truncated));
        assert_eq!(cursor, 3);
    }
}
