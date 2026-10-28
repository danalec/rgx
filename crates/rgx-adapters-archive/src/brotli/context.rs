// SPDX-License-Identifier: Apache-2.0

//! RFC 7932 Section 7.1: the literal context ID, from the last two bytes
//! of the uncompressed stream.
//!
//! The three lookup tables are in `tables.rs`, transcribed from the RFC
//! and CRC-checked there. Which of them is consulted, and how, is the
//! context mode -- two bits per literal block type, read in the meta-block
//! header.

use super::tables::{LUT0, LUT1, LUT2};

/// The context ID for the next literal: 0..63, always.
pub fn literal_context(mode: u8, p1: u8, p2: u8) -> u8 {
    match mode & 3 {
        // LSB6: the six least significant bits of the last byte.
        0 => p1 & 0x3F,
        // MSB6: the six most significant bits of the last byte.
        1 => p1 >> 2,
        // UTF8: shaped for text, where a byte's position in a multi-byte
        // sequence and the byte before it both matter.
        2 => LUT0[p1 as usize] | LUT1[p2 as usize],
        // Signed: shaped for sequences of small signed integers, where
        // the low three bits of each of the last two bytes are the sign
        // and the most significant bit.
        _ => (LUT2[p1 as usize] << 3) | LUT2[p2 as usize],
    }
}
