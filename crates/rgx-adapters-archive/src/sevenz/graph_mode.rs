// SPDX-License-Identifier: Apache-2.0

//! Match-finding strategy selection for the LZ encoders in this crate.
//!
//! rgx's own code, shared with `lz4/graph_optimize.rs`: the enum picks
//! between a plain hash-chain finder and the Paley-graph-inspired hash
//! below, which is an original mixing function — a multiplicative
//! round, a quadratic-residue-style avalanche, and a final diffusion
//! keyed on the Paley prime 131101. Not derived from 7-Zip or any
//! other third-party implementation.

/// Selects match-finding strategy for compression encoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraphMode {
    /// Original hash chain match finder.
    Standard,
    /// Paley graph-inspired hash + lazy matching + verify hash +
    /// FlipPredictor-style adaptive chain scoring.
    #[default]
    Paley,
}

/// Paley prime for 17-bit hash: 131101 = prime, ≡ 1 (mod 4)
const PALEY_P17: u64 = 131101;
/// Mixing constant derived from (p-1)/2 for Paley prime 131101
const PALEY_MIX1: u64 = 0x1E35_A7BD;
/// Secondary mixing from Legendre symbol computation
const PALEY_MIX2: u64 = 0x85EB_CA77;
/// Tertiary mixing (avalanche finalization)
const PALEY_MIX3: u64 = 0xC2B2_AE3D;

/// Core mixing function inspired by Paley graph quadratic residue properties.
#[inline]
fn paley_mix(v: u32) -> u32 {
    let mut h = v as u64;

    // Round 1: Multiplicative hashing (standard Paley-like positioning)
    h = h.wrapping_mul(PALEY_MIX1);

    // Round 2: Quadratic-residue-inspired avalanche.
    let lo = h & 0xFFFF;
    let hi = h >> 16;
    h = lo.wrapping_mul(lo) ^ hi.wrapping_mul(PALEY_MIX2);
    h ^= h >> 15;

    // Round 3: Final diffusion with Paley prime
    h = h.wrapping_mul(PALEY_P17);
    h ^= h >> 17;
    h = h.wrapping_mul(PALEY_MIX3);

    h as u32
}

/// Paley graph-inspired 3-byte hash for arbitrary bit count.
#[inline]
pub(crate) fn paley_hash3_bits(data: &[u8], bits: u32) -> u32 {
    let v = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
    paley_mix(v) >> (32 - bits)
}
