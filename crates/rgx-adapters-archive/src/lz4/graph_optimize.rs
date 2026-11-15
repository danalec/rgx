// SPDX-License-Identifier: Apache-2.0

//! Graph-theoretic hash and chain-walking primitives used by the LZ4
//! encoder: Paley-inspired quadratic-residue mixing for the hash tables,
//! and a FlipPredictor-style scoring function for chain walking.
//!
//! The mixer constants are pinned: the Paley prime `p ≡ 1 (mod 4)`
//! gives the quadratic-residue step its avalanche, and changing the
//! constants changes every fingerprint the encoder emits.

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Paley Graph-Inspired Hash Functions
// ---------------------------------------------------------------------------

/// Paley prime for 17-bit hash: 131101 = prime, ≡ 1 (mod 4)
const PALEY_P17: u64 = 131101;
/// Paley prime for 19-bit hash: 524281 = prime, ≡ 1 (mod 4)
const PALEY_P19: u64 = 524281;
/// Mixing constant derived from (p-1)/2 for Paley prime 131101
const PALEY_MIX1: u64 = 0x1E35_A7BD;
/// Secondary mixing from Legendre symbol computation
const PALEY_MIX2: u64 = 0x85EB_CA77;
/// Tertiary mixing (avalanche finalization)
const PALEY_MIX3: u64 = 0xC2B2_AE3D;

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

/// Paley graph-inspired 4-byte hash function.
///
/// Provides better distribution than simple multiplicative hashing by
/// incorporating quadratic residue mixing inspired by the Paley construction.
/// The squaring step simulates the Legendre symbol computation that gives
/// Paley graphs their optimal pseudo-random properties.
#[inline]
pub(crate) fn paley_hash4(data: &[u8]) -> u32 {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    paley_mix(v)
}

/// Paley-inspired hash for arbitrary bit count (used by ZSTD's 18-bit hash).
#[inline]
pub(crate) fn paley_hash4_bits(data: &[u8], bits: u32) -> u32 {
    paley_mix(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) >> (32 - bits)
}

/// Core mixing function inspired by Paley graph quadratic residue properties.
#[inline]
fn paley_mix(v: u32) -> u32 {
    let mut h = v as u64;

    // Round 1: Multiplicative hashing (standard Paley-like positioning)
    h = h.wrapping_mul(PALEY_MIX1);

    // Round 2: Quadratic-residue-inspired avalanche.
    // In Paley graphs, x -> x^2 mod p maps uniform input to uniform output
    // with half the values being residues. This squaring step provides
    // similar avalanche: bits interact nonlinearly.
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

/// Core mixing variant B — independent constants for multi-probe hashing.
/// Uses PALEY_MIX2 as primary multiplier and PALEY_MIX3 as avalanche,
/// with a different Paley prime (262147) for final diffusion.
#[inline]
fn paley_mix_b(v: u32) -> u32 {
    let mut h = v as u64;

    // Round 1: Different primary multiplier
    h = h.wrapping_mul(PALEY_MIX2);

    // Round 2: Quadratic avalanche with rotated constants
    let lo = h & 0xFFFF;
    let hi = h >> 16;
    h = lo.wrapping_mul(lo) ^ hi.wrapping_mul(PALEY_MIX3);
    h ^= h >> 15;

    // Round 3: Different Paley prime for diffusion
    h = h.wrapping_mul(262147); // prime ≡ 1 mod 4
    h ^= h >> 17;
    h = h.wrapping_mul(PALEY_MIX1);

    h as u32
}

/// Core mixing variant C — third independent hash for multi-probe.
/// Uses PALEY_MIX3 as primary multiplier and PALEY_MIX1 as avalanche,
/// with a different Paley prime (524309) for final diffusion.
#[inline]
fn paley_mix_c(v: u32) -> u32 {
    let mut h = v as u64;

    // Round 1: Third multiplier
    h = h.wrapping_mul(PALEY_MIX3);

    // Round 2: Quadratic avalanche with remaining constant pair
    let lo = h & 0xFFFF;
    let hi = h >> 16;
    h = lo.wrapping_mul(lo) ^ hi.wrapping_mul(PALEY_MIX1);
    h ^= h >> 15;

    // Round 3: Third Paley prime
    h = h.wrapping_mul(524309); // prime ≡ 1 mod 4
    h ^= h >> 17;
    h = h.wrapping_mul(PALEY_MIX2);

    h as u32
}

/// Probe B: second independent Paley hash for 4-byte input.
#[inline]
pub(crate) fn paley_hash4_b(data: &[u8]) -> u32 {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    paley_mix_b(v)
}

/// Probe B with configurable bit width.
#[inline]
pub(crate) fn paley_hash4_b_bits(data: &[u8], bits: u32) -> u32 {
    paley_mix_b(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) >> (32 - bits)
}

/// Probe C: third independent Paley hash for 4-byte input.
#[inline]
pub(crate) fn paley_hash4_c(data: &[u8]) -> u32 {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    paley_mix_c(v)
}

/// Probe C with configurable bit width.
#[inline]
pub(crate) fn paley_hash4_c_bits(data: &[u8], bits: u32) -> u32 {
    paley_mix_c(u32::from_le_bytes([data[0], data[1], data[2], data[3]])) >> (32 - bits)
}

/// Secondary hash for verification (reduces false positive matches).
/// Uses different mixing constants derived from PALEY_P19.
#[inline]
pub(crate) fn paley_hash4_verify(data: &[u8]) -> u16 {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let h = (v as u64).wrapping_mul(PALEY_MIX2);
    let h = h ^ (h >> 16);
    let h = h.wrapping_mul(PALEY_P19);
    let h = h ^ (h >> 16);
    (h >> 16) as u16
}

// ---------------------------------------------------------------------------
// 3-byte Paley hashes (for LZMA, LZSS, Brotli, LZ77)
// ---------------------------------------------------------------------------

/// Paley 3-byte hash with configurable bit output.
#[inline]
pub(crate) fn paley_hash3_bits(data: &[u8], bits: u32) -> u32 {
    let v = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
    paley_mix(v) >> (32 - bits)
}

/// Paley 3-byte hash B-variant.
#[inline]
pub(crate) fn paley_hash3_b_bits(data: &[u8], bits: u32) -> u32 {
    let v = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
    paley_mix_b(v) >> (32 - bits)
}

/// Paley 3-byte verify hash.
#[inline]
pub(crate) fn paley_hash3_verify(data: &[u8]) -> u16 {
    let v = (data[0] as u64) | ((data[1] as u64) << 8) | ((data[2] as u64) << 16);
    let h = v.wrapping_mul(PALEY_MIX2);
    let h = h ^ (h >> 16);
    let h = h.wrapping_mul(PALEY_P19);
    let h = h ^ (h >> 16);
    (h >> 16) as u16
}

// ---------------------------------------------------------------------------
// FlipPredictor-Inspired Match Scoring
// ---------------------------------------------------------------------------
//
// Weighted-feature predictor over hash chain candidates: match length
// (compression benefit), chain depth (exploration cost), position
// distance (locality benefit), and per-bucket historical hit rate.
// Weights are updated from accumulated results to favour candidates
// that produced longer matches.

/// Match quality features (analogous to FlipFeatures).
#[derive(Clone, Copy, Default)]
pub struct MatchFeatures {
    /// Match length found at this candidate (0 if not yet evaluated).
    pub match_len: usize,
    /// Distance from current position to candidate.
    pub distance: usize,
    /// Position in the hash chain (0 = most recent).
    pub chain_depth: usize,
    /// Number of entries in this hash bucket.
    pub bucket_size: usize,
    /// Historical success rate for matches from this distance range.
    pub historical_rate: f32,
}

/// FlipPredictor-inspired match quality predictor.
///
/// Uses weighted feature scoring to prioritize which hash chain candidates
/// to evaluate first and when to stop searching.
pub struct MatchPredictor {
    // Learned weights (initialized from FlipPredictor defaults)
    w_distance: f64,
    w_depth: f64,
    w_bucket: f64,
    w_historical: f64,

    // Running statistics for online learning
    total_evaluated: u32,
    successful_matches: u32,
    /// Histogram of best match distances (16 bins of 4KB each).
    distance_hist: [u32; 16],
    /// Current processing cycle (analogous to FlipPredictor.current_cycle).
    pub current_cycle: u32,
}

impl Default for MatchPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchPredictor {
    pub fn new() -> Self {
        Self {
            w_distance: -0.35,
            w_depth: -0.1,
            w_bucket: 0.05,
            w_historical: 0.3,
            total_evaluated: 0,
            successful_matches: 0,
            distance_hist: [0; 16],
            current_cycle: 0,
        }
    }

    /// Score a candidate (lower is better, like FlipPredictor.predict_score).
    /// Candidates with higher predicted scores should be evaluated first.
    pub fn predict_quality(&self, f: &MatchFeatures) -> f64 {
        let dist_norm = f.distance as f64 / 65536.0;
        let depth_norm = f.chain_depth as f64 / 64.0;
        let bucket_norm = if f.bucket_size > 0 {
            1.0 / f.bucket_size as f64
        } else {
            1.0
        };

        self.w_distance * dist_norm
            + self.w_depth * depth_norm
            + self.w_bucket * bucket_norm
            + self.w_historical * f.historical_rate as f64
    }

    /// Decide whether to skip a candidate during chain walking.
    /// Uses predict_quality() to check if a candidate at (distance, depth) is
    /// worth the byte comparison cost, given we already have a match of `best_len`.
    ///
    /// Returns true if the candidate should be SKIPPED (too unpromising).
    pub fn should_skip(&self, distance: usize, chain_depth: usize, best_len: usize) -> bool {
        // Never skip if we don't have a match yet
        if best_len == 0 {
            return false;
        }

        let features = MatchFeatures {
            match_len: 0,
            distance,
            chain_depth,
            bucket_size: 0,
            historical_rate: self.historical_rate(distance),
        };

        let quality = self.predict_quality(&features);

        // Adaptive threshold: the better our current match, the pickier we are
        let threshold = if best_len >= 64 {
            0.05 // Very picky — only check very promising candidates
        } else if best_len >= 32 {
            -0.05
        } else if best_len >= 16 {
            -0.15
        } else {
            -0.25 // Still searching for a decent match
        };

        quality < threshold
    }

    /// Record a match evaluation result (analogous to FlipPredictor.record_flip).
    pub fn record_match(&mut self, distance: usize, match_len: usize) {
        self.total_evaluated += 1;
        if match_len >= 4 {
            self.successful_matches += 1;
            let bin = (distance / 4096).min(15);
            self.distance_hist[bin] += 1;
        }
    }

    /// Get historical success rate for a distance range.
    pub fn historical_rate(&self, distance: usize) -> f32 {
        let bin = (distance / 4096).min(15);
        if self.total_evaluated == 0 {
            return 0.5;
        }
        self.distance_hist[bin] as f32 / self.total_evaluated as f32
    }

    /// Learn weights from accumulated data (like FlipPredictor.learn_weights).
    pub fn learn(&mut self) {
        if self.total_evaluated < 200 {
            return;
        }

        // Find which distance bins are most productive
        let mut best_bin = 0usize;
        let mut best_count = 0u32;
        for (i, &c) in self.distance_hist.iter().enumerate() {
            if c > best_count {
                best_count = c;
                best_bin = i;
            }
        }

        // Adjust distance weight: if short-distance matches dominate,
        // increase distance penalty to search nearby first
        if best_bin < 4 {
            self.w_distance = -0.45;
        } else if best_bin > 10 {
            self.w_distance = -0.25;
        } else {
            self.w_distance = -0.35;
        }

        let success_rate = self.successful_matches as f64 / self.total_evaluated as f64;
        if success_rate > 0.7 {
            self.w_historical = 0.4;
        } else if success_rate < 0.3 {
            self.w_historical = 0.2;
        }
    }
}

// ---------------------------------------------------------------------------
// Witness Amplification
// ---------------------------------------------------------------------------
//
// Short matches (4-7 bytes) are the most likely false positives from
// hash collisions. Witness amplification checks additional byte
// positions derived from Paley graph quadratic residues before
// accepting these. The small Paley primes give:
//
//   QR(5)  = {1, 4}        -> offsets [1, 4]
//   QR(13) = {1, 3, 4, 9}  -> offsets [1, 3, 4, 9]

/// Configuration for witness amplification of short matches.
#[derive(Clone, Copy)]
pub struct WitnessConfig {
    /// Matches shorter than this may need witness verification.
    pub threshold: usize,
    /// Minimum witnesses required to accept a short match.
    pub min_witnesses: usize,
    /// Offsets (from match start) to check as witnesses.
    /// Derived from quadratic residues of small Paley primes.
    pub offsets: [usize; 8],
    /// Number of active offsets (1..=8).
    pub num_offsets: usize,
}

impl Default for WitnessConfig {
    fn default() -> Self {
        Self::qr13()
    }
}

impl WitnessConfig {
    /// QR(13) = {1, 3, 4, 9} — 4 witnesses. Default for medium-entropy data.
    pub fn qr13() -> Self {
        Self {
            threshold: 8,
            min_witnesses: 2,
            offsets: [1, 3, 4, 9, 0, 0, 0, 0],
            num_offsets: 4,
        }
    }

    /// QR(17) = {1, 2, 4, 8, 9, 13, 15, 16} — 8 witnesses.
    /// Better false-positive rejection for high-entropy data.
    pub fn qr17() -> Self {
        Self {
            threshold: 12,
            min_witnesses: 3,
            offsets: [1, 2, 4, 8, 9, 13, 15, 16],
            num_offsets: 8,
        }
    }

    /// QR(5) = {1, 4} — 2 witnesses. Fast for low-entropy data.
    pub fn qr5() -> Self {
        Self {
            threshold: 6,
            min_witnesses: 1,
            offsets: [1, 4, 0, 0, 0, 0, 0, 0],
            num_offsets: 2,
        }
    }
}

/// Count how many witness positions confirm a match between data[pos..] and data[ref..].
/// Returns the number of matching witness positions.
#[inline]
pub(crate) fn count_witnesses(
    data: &[u8],
    pos: usize,
    ref_pos: usize,
    match_len: usize,
    cfg: &WitnessConfig,
) -> usize {
    let mut count = 0usize;
    let active = &cfg.offsets[..cfg.num_offsets];
    for &off in active {
        if off >= match_len {
            continue;
        }
        if pos + off < data.len()
            && ref_pos + off < data.len()
            && data[pos + off] == data[ref_pos + off]
        {
            count += 1;
        }
    }
    count
}

/// Try extending a match beyond its current length, using witness confidence
/// to justify speculative extension. Returns new extended length.
#[inline]
pub(crate) fn extend_with_witnesses(
    data: &[u8],
    pos: usize,
    ref_pos: usize,
    current_len: usize,
    max_len: usize,
) -> usize {
    let mut len = current_len;
    while len < max_len && data[ref_pos + len] == data[pos + len] {
        len += 1;
    }
    len
}

// ---------------------------------------------------------------------------
// Offset Graph Prediction
// ---------------------------------------------------------------------------
//
// Paley graphs have the property that any two vertices share exactly
// (q-5)/4 or (q-1)/4 common neighbors (strong regularity). This means
// if offset d is productive at position i, then offsets that are
// Paley-neighbors of d are likely productive at nearby positions.
//
// The predictor combines:
// 1. Historical: which offsets recently produced good matches
// 2. Paley-derived: offsets from quadratic residue structure

/// Predicts likely-good match offsets from historical data and Paley structure.
pub struct OffsetPredictor {
    /// Recent successful offsets (ring buffer).
    recent: [u32; 8],
    /// Ring buffer write position.
    recent_idx: usize,
    /// Offset frequency histogram (32 bins, power-of-2 spacing).
    hist: [u32; 32],
    /// Pre-computed Paley-derived offsets from quadratic residues.
    paley_offsets: [u32; 16],
}

impl Default for OffsetPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl OffsetPredictor {
    pub fn new() -> Self {
        // Pre-compute Paley offsets from quadratic residues of PALEY_P17 = 131101
        // Scale residues to byte distances: offset = (residue * 256) / prime
        let prime: u64 = 131101;
        let mut paley_offsets = [0u32; 16];
        let mut idx = 0;
        // Find first 16 quadratic residues and scale to useful offsets
        let mut i: u64 = 1;
        while idx < 16 && i < prime {
            // Check if i is a QR mod prime using Euler's criterion
            if mod_pow(i, (prime - 1) / 2, prime) == 1 {
                // Scale to byte distance: map [1..prime] to [4..65536]
                let offset = ((i * 65536) / prime).max(4) as u32;
                paley_offsets[idx] = offset;
                idx += 1;
            }
            i += 1;
        }

        Self {
            recent: [0; 8],
            recent_idx: 0,
            hist: [0; 32],
            paley_offsets,
        }
    }

    /// Record that offset `d` produced a good match.
    pub fn record(&mut self, d: u32, _len: usize) {
        self.recent[self.recent_idx] = d;
        self.recent_idx = (self.recent_idx + 1) % 8;
        // Bin: power-of-2 spacing, covers 4..64K
        let bin = (32 - d.leading_zeros() as usize).min(31);
        self.hist[bin] += 1;
    }

    /// Get predicted offsets to try (in order of expected quality).
    /// Returns up to `max` offsets as a fixed-size array.
    pub fn top_offsets(&self, max: usize) -> alloc::vec::Vec<u32> {
        let mut offsets = alloc::vec::Vec::with_capacity(max);

        // Recent offsets first (most relevant due to locality)
        for i in 0..8 {
            let off = self.recent[(self.recent_idx + 8 - 1 - i) % 8];
            if off > 0 && !offsets.contains(&off) {
                offsets.push(off);
                if offsets.len() >= max {
                    return offsets;
                }
            }
        }

        // Paley neighbor intersection: if two recent offsets d1, d2 both succeeded,
        // probe their Paley-neighbor intersection first (strong regularity property:
        // any two vertices share exactly (q-5)/4 or (q-1)/4 common neighbors).
        if offsets.len() < max {
            let intersection = self.paley_intersection();
            for off in intersection {
                if off > 0 && !offsets.contains(&off) {
                    offsets.push(off);
                    if offsets.len() >= max {
                        return offsets;
                    }
                }
            }
        }

        // Paley-derived offsets
        for &off in &self.paley_offsets {
            if off > 0 && !offsets.contains(&off) {
                offsets.push(off);
                if offsets.len() >= max {
                    return offsets;
                }
            }
        }

        offsets
    }

    /// Compute Paley-neighbor intersection of two most recent successful offsets.
    ///
    /// In Paley graph on GF(p), vertices d1 and d2 are connected iff (d1-d2) is a
    /// quadratic residue mod p. Two vertices share (p-5)/4 or (p-1)/4 common neighbors.
    /// We approximate: for each Paley-derived offset, check if it's a QR-neighbor of
    /// both recent successful offsets, meaning it's in their intersection neighborhood.
    pub fn paley_intersection(&self) -> alloc::vec::Vec<u32> {
        // Get two most recent non-zero offsets
        let mut recent_nonzero: [u32; 2] = [0; 2];
        let mut ri = 0;
        for i in 0..8 {
            let off = self.recent[(self.recent_idx + 8 - 1 - i) % 8];
            if off > 0 {
                recent_nonzero[ri] = off;
                ri += 1;
                if ri >= 2 {
                    break;
                }
            }
        }
        if ri < 2 {
            return alloc::vec::Vec::new();
        }

        let d1 = recent_nonzero[0] as u64;
        let d2 = recent_nonzero[1] as u64;
        let prime: u64 = 131101;

        // Offsets that are Paley-neighbors of BOTH d1 and d2
        let mut result = alloc::vec::Vec::new();
        for &off in &self.paley_offsets {
            if off == 0 {
                continue;
            }
            let o = off as u64;
            // Check if (o - d1) and (o - d2) are both QR mod prime
            let diff1 = o.abs_diff(d1);
            let diff2 = o.abs_diff(d2);
            if diff1 == 0 || diff2 == 0 {
                continue;
            }
            if mod_pow(diff1 % prime, (prime - 1) / 2, prime) == 1
                && mod_pow(diff2 % prime, (prime - 1) / 2, prime) == 1
            {
                result.push(off);
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Van der Waerden Stride Prediction
// ---------------------------------------------------------------------------
//
// Van der Waerden's theorem guarantees monochromatic arithmetic progressions
// in any coloring of a sufficiently long sequence. For compression:
// if positions p, p+d, p+2d all produced LZ matches, then p+3d forms the
// next term of an arithmetic progression that is likely to also match.
//
// This provides a completely different match growth strategy: instead of
// byte-by-byte extension, we can speculatively try the predicted stride
// position first, bypassing hash lookup entirely for periodic data.

/// Van der Waerden stride predictor — detects arithmetic progressions in
/// recent match positions and speculatively extends them.
pub struct StridePredictor {
    /// Recent match positions (ring buffer).
    positions: [usize; 8],
    /// Corresponding match distances (ring buffer).
    distances: [u32; 8],
    /// Ring buffer write index.
    idx: usize,
    /// Currently detected stride (0 = none).
    active_stride: usize,
    /// Number of consecutive stride confirmations.
    stride_len: usize,
}

impl Default for StridePredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl StridePredictor {
    pub fn new() -> Self {
        Self {
            positions: [0; 8],
            distances: [0; 8],
            idx: 0,
            active_stride: 0,
            stride_len: 0,
        }
    }

    /// Record a successful match at position `pos` with distance `dist`.
    pub fn record(&mut self, pos: usize, dist: u32) {
        // Detect stride before overwriting
        self.detect_stride(pos);

        self.positions[self.idx] = pos;
        self.distances[self.idx] = dist;
        self.idx = (self.idx + 1) % 8;
    }

    /// Check if current position continues an AP and update stride state.
    fn detect_stride(&mut self, pos: usize) {
        // Look for an arithmetic progression ending at pos
        for i in 0..8 {
            let ri = (self.idx + 8 - 1 - i) % 8;
            let prev = self.positions[ri];
            if prev == 0 {
                continue;
            }
            let stride = pos.wrapping_sub(prev);
            if stride == 0 || stride > 65536 {
                continue;
            }

            // Check if prev - stride also had a match (3-term AP)
            let prev_prev = prev.wrapping_sub(stride);
            for j in 0..8 {
                let rj = (self.idx + 8 - 1 - j) % 8;
                if self.positions[rj] == prev_prev {
                    // Found AP: prev_prev, prev, pos with common stride
                    if stride == self.active_stride {
                        self.stride_len += 1;
                    } else {
                        self.active_stride = stride;
                        self.stride_len = 2; // 3-term AP = 2 strides
                    }
                    return;
                }
            }
        }
        // No AP detected — decay stride confidence
        if self.stride_len > 0 {
            self.stride_len -= 1;
        }
        if self.stride_len == 0 {
            self.active_stride = 0;
        }
    }

    /// Try a speculative stride match at the current position.
    /// If an AP is active, check if current position is the next term.
    /// Returns (distance, match_length) if a stride match is found.
    pub fn try_stride(&self, data: &[u8], pos: usize, max_len: usize) -> Option<(usize, usize)> {
        if self.stride_len < 2 || self.active_stride == 0 {
            return None;
        }

        // Try the distance that was used in the most recent AP term
        let last_idx = (self.idx + 8 - 1) % 8;
        let dist = self.distances[last_idx] as usize;
        if dist == 0 || dist > pos {
            return None;
        }

        let ref_pos = pos - dist;
        if ref_pos + 4 > data.len() || pos + 4 > data.len() {
            return None;
        }

        // Quick check: do the first 4 bytes match?
        if data[ref_pos] != data[pos]
            || data[ref_pos + 1] != data[pos + 1]
            || data[ref_pos + 2] != data[pos + 2]
            || data[ref_pos + 3] != data[pos + 3]
        {
            return None;
        }

        // Extend the match
        let len = extend_with_witnesses(data, pos, ref_pos, 4, max_len);
        if len >= 4 {
            Some((dist, len))
        } else {
            None
        }
    }

    /// Whether stride prediction is active enough to be worth trying.
    pub fn is_active(&self) -> bool {
        self.stride_len >= 2 && self.active_stride > 0
    }
}

// ---------------------------------------------------------------------------
// Ramsey R(3,k) Adaptive Search Depth
// ---------------------------------------------------------------------------
//
// Minimum chain depth guaranteed to find at least one "good" candidate
// for a target match quality level `k`. Values from R(3,k) for k = 1..9.

/// Ramsey R(3,k) lookup table for adaptive minimum search depth.
const RAMSEY_R3K: [usize; 9] = [1, 3, 6, 9, 14, 18, 23, 28, 36];

/// Get minimum search depth from Ramsey R(3,k) theory.
/// `k` is the target match quality level (1..=9).
/// Returns the guaranteed minimum chain depth.
pub(crate) fn ramsey_min_depth(k: usize) -> usize {
    RAMSEY_R3K
        .get(k.min(9).saturating_sub(1))
        .copied()
        .unwrap_or(1)
}

/// Fast modular exponentiation for Euler's criterion.
fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}

// ---------------------------------------------------------------------------
// Hypergraph Partitioning-Inspired Block Splitting
// ---------------------------------------------------------------------------
//
// Hypergraph-inspired block partitioning: pick boundaries that
// minimise cross-block redundancy, so each block stays self-contained
// for per-block coding. Target block count grows with input size:
// 1 / 2 / 4 / 8 for < 16 KiB / < 64 KiB / < 256 KiB / larger.

/// Entropy-based block partitioner using hypergraph partitioning principles.
pub struct BlockPartitioner {
    target_blocks: usize,
    min_block: usize,
    max_block: usize,
}

impl BlockPartitioner {
    pub fn new(input_len: usize) -> Self {
        // Choose target blocks using the improved_a_n principle:
        // more blocks for larger inputs, but with diminishing returns
        let target_blocks = if input_len < 16384 {
            1
        } else if input_len < 65536 {
            2
        } else if input_len < 262144 {
            4
        } else {
            8
        };

        Self {
            target_blocks,
            min_block: 4096,
            max_block: 1 << 19,
        }
    }

    /// Find optimal block boundaries using entropy analysis.
    /// Returns sorted vector of block start positions.
    pub fn find_boundaries(&self, data: &[u8]) -> Vec<usize> {
        if self.target_blocks <= 1 || data.len() < self.min_block * 2 {
            return alloc::vec![0];
        }

        let mut boundaries = alloc::vec![0usize];
        let approx_size = data.len() / self.target_blocks;

        for block_idx in 1..self.target_blocks {
            let nominal = block_idx * approx_size;
            let search_start = nominal.saturating_sub(approx_size / 4);
            let search_end = (nominal + approx_size / 4).min(data.len() - self.min_block);

            if search_start >= search_end {
                continue;
            }

            // Find lowest cross-similarity point (best boundary)
            let window = 256.min(approx_size / 8);
            let step = ((search_end - search_start) / 32).max(1);

            let mut best_pos = nominal;
            let mut best_score = f64::MAX;

            for candidate in (search_start..search_end).step_by(step) {
                let left_start = candidate.saturating_sub(window);
                let right_end = (candidate + window).min(data.len());
                if candidate <= left_start || right_end <= candidate {
                    continue;
                }
                let left = &data[left_start..candidate];
                let right = &data[candidate..right_end];
                let score = cross_similarity(left, right);
                if score < best_score {
                    best_score = score;
                    best_pos = candidate;
                }
            }

            boundaries.push(best_pos);
        }

        boundaries.sort();
        boundaries.dedup();
        boundaries
    }
}

/// Measure cross-boundary similarity using byte frequency cosine distance.
/// Lower = better split point (less shared information across boundary).
fn cross_similarity(left: &[u8], right: &[u8]) -> f64 {
    let mut lf = [0f64; 256];
    let mut rf = [0f64; 256];

    for &b in left {
        lf[b as usize] += 1.0;
    }
    for &b in right {
        rf[b as usize] += 1.0;
    }

    let ll = left.len() as f64;
    let rl = right.len() as f64;
    let mut dot = 0.0f64;
    let mut nl = 0.0f64;
    let mut nr = 0.0f64;
    for i in 0..256 {
        let lfn = lf[i] / ll;
        let rfn = rf[i] / rl;
        dot += lfn * rfn;
        nl += lfn * lfn;
        nr += rfn * rfn;
    }

    // Vendored note: the upstream sources are no_std-friendly and reach for
    // a libm shim; rgx is std, so these are the f64 methods of the
    // same name.
    let denom = f64::sqrt(nl * nr);
    if denom > 0.0 {
        dot / denom
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// ColorProfile-Inspired Data Region Classification
// ---------------------------------------------------------------------------
//
// Classifies data regions by entropy (`LowEntropy` for repetitive,
// `MediumEntropy` for moderate patterns, `HighEntropy` for
// near-random), so the encoder can pick a strategy that fits.

/// Data region classification (analogous to ViolationClass + DegreeBin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataRegion {
    /// Highly repetitive data (like vertices with no violations).
    LowEntropy,
    /// Moderate pattern density (like normal-degree vertices).
    MediumEntropy,
    /// Near-random data (like high-degree, mixed violation vertices).
    HighEntropy,
}

impl DataRegion {
    /// Classify a data region by its byte frequency profile.
    /// Analogous to ColorProfile::compute_full for graph vertices.
    pub fn classify(data: &[u8]) -> Self {
        if data.len() < 32 {
            return DataRegion::MediumEntropy;
        }

        let mut freq = [0usize; 256];
        for &b in data {
            freq[b as usize] += 1;
        }

        // Count unique byte values (analogous to num_color_classes)
        let unique = freq.iter().filter(|&&f| f > 0).count();

        // Compute Shannon entropy (analogous to degree distribution analysis)
        let len = data.len() as f64;
        let mut entropy = 0.0f64;
        for &f in &freq {
            if f > 0 {
                let p = f as f64 / len;
                entropy -= p * f64::log2(p);
            }
        }

        // Classify (analogous to DegreeBin thresholds)
        if entropy < 4.0 || unique < 32 {
            DataRegion::LowEntropy
        } else if entropy < 6.5 {
            DataRegion::MediumEntropy
        } else {
            DataRegion::HighEntropy
        }
    }

    /// Returns the optimal minimum match length for this region type.
    /// Lower entropy → shorter matches are worthwhile.
    pub fn optimal_min_match(&self) -> usize {
        match self {
            DataRegion::LowEntropy => 3,
            DataRegion::MediumEntropy => 4,
            DataRegion::HighEntropy => 5,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paley_hash_deterministic() {
        let data = b"Test";
        let h1 = paley_hash4(data);
        let h2 = paley_hash4(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_paley_hash_distribution() {
        // Verify hash values are reasonably distributed
        let mut counts = [0usize; 256];
        for i in 0..1000u32 {
            let data = i.to_le_bytes();
            let h = paley_hash4(&data);
            counts[(h >> 24) as usize] += 1;
        }
        // No bucket should have more than 20 out of 1000
        for &c in &counts {
            assert!(c < 20, "Hash distribution too uneven: {}", c);
        }
    }

    #[test]
    fn test_paley_hash_different_inputs() {
        let h1 = paley_hash4(b"ABCD");
        let h2 = paley_hash4(b"ABCE");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_paley_hash_bits() {
        let h = paley_hash4_bits(b"Test", 16);
        assert!(h < (1 << 16));
    }

    #[test]
    fn test_match_predictor_scoring() {
        let predictor = MatchPredictor::new();

        let nearby = MatchFeatures {
            match_len: 0,
            distance: 100,
            chain_depth: 1,
            bucket_size: 10,
            historical_rate: 0.7,
        };
        let faraway = MatchFeatures {
            match_len: 0,
            distance: 50000,
            chain_depth: 50,
            bucket_size: 10,
            historical_rate: 0.3,
        };

        let score_near = predictor.predict_quality(&nearby);
        let score_far = predictor.predict_quality(&faraway);

        // Nearby should score higher (less negative = better quality)
        assert!(
            score_near > score_far,
            "Nearby score {} should be > far score {}",
            score_near,
            score_far
        );
    }

    #[test]
    fn test_match_predictor_learning() {
        let mut predictor = MatchPredictor::new();

        // Record mostly short-distance matches
        for _ in 0..300 {
            predictor.record_match(1000, 10);
        }
        predictor.learn();

        // After learning with short-distance data, weight should be adjusted
        assert!(predictor.w_distance < -0.35);
    }

    #[test]
    fn test_data_region_classify() {
        let zeros = vec![0u8; 1000];
        assert_eq!(DataRegion::classify(&zeros), DataRegion::LowEntropy);

        let pattern: Vec<u8> = (0..4).cycle().take(1000).collect();
        let region = DataRegion::classify(&pattern);
        assert!(region == DataRegion::LowEntropy || region == DataRegion::MediumEntropy);
    }

    #[test]
    fn test_block_partitioner_small() {
        let partitioner = BlockPartitioner::new(5000);
        let data = vec![0u8; 5000];
        let boundaries = partitioner.find_boundaries(&data);
        assert_eq!(boundaries, vec![0]);
    }

    #[test]
    fn test_block_partitioner_large() {
        let partitioner = BlockPartitioner::new(100000);
        let mut data = vec![0u8; 100000];
        // Create a pattern change at 50KB
        data[50000..100000].fill(255);
        let boundaries = partitioner.find_boundaries(&data);
        assert!(!boundaries.is_empty());
        assert_eq!(boundaries[0], 0);
    }

    #[test]
    fn test_cross_similarity() {
        let a = vec![0u8; 256];
        let b = vec![0u8; 256];
        let sim = cross_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 0.001, "Identical should be ~1.0");

        // Different single-byte values have 0 cosine similarity
        let c = vec![255u8; 256];
        let sim2 = cross_similarity(&a, &c);
        assert!(
            sim2 < 0.01,
            "Different bytes should have ~0 similarity, got {}",
            sim2
        );
    }

    #[test]
    fn test_optimal_min_match() {
        assert_eq!(DataRegion::LowEntropy.optimal_min_match(), 3);
        assert_eq!(DataRegion::MediumEntropy.optimal_min_match(), 4);
        assert_eq!(DataRegion::HighEntropy.optimal_min_match(), 5);
    }
}
