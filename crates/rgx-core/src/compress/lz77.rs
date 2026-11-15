// SPDX-License-Identifier: Apache-2.0

//! The LZ77 sliding-window stage of DEFLATE.
//!
//! Independent reimplementation of the published LZ77 parameters — a
//! 32 KiB window, matches of 3..=258 bytes at distances 1..=32768 —
//! written from the RFC 1951 definition of what a match reference means
//! rather than from any implementation's source. The encoder turns bytes
//! into literal/match tokens for the block encoders to entropy-code; the
//! decoder replays tokens against a sliding window, and is the half
//! every .gz/.zip payload goes through.
//!
//! The decoder's contract, which the encoder never sees: a match whose
//! distance reaches past the window is refused, and the output ceiling
//! is debited as bytes are emitted, never afterwards.

use super::cap::OutputCap;
use alloc::vec;
use alloc::vec::Vec;

/// Default window size for DEFLATE (32KB).
pub const DEFAULT_WINDOW_SIZE: usize = 32 * 1024;

/// Minimum match length.
pub const MIN_MATCH: usize = 3;

/// Maximum match length for DEFLATE.
pub const MAX_MATCH: usize = 258;

/// Maximum distance for DEFLATE.
pub const MAX_DISTANCE: usize = 32 * 1024;

/// LZ77 match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Distance back from current position.
    pub distance: u16,
    /// Length of the match.
    pub length: u16,
}

/// LZ77 compressor.
#[derive(Debug)]
pub struct Lz77Encoder {
    /// Sliding window buffer: the whole input for one compress call.
    window: Vec<u8>,
    /// Head of each hash bucket: the most recent position whose 3-byte
    /// prefix hashed there, or `NONE`.
    head: Vec<usize>,
    /// `prev[p]` chains position `p` to the previous position with the
    /// same hash, which is what bounds the search to a window's worth of
    /// candidates instead of every earlier byte.
    prev: Vec<usize>,
    /// Compression level (1-9).
    level: u8,
    /// Maximum chain depth for match searching.
    max_chain: usize,
    /// How far ahead lazy matching may look past a found match.
    max_lazy: usize,
}

/// Chain terminator: no earlier position in the bucket.
const NONE: usize = usize::MAX;

impl Lz77Encoder {
    /// Create a new LZ77 encoder with default settings.
    pub fn new() -> Self {
        Self::with_level(6)
    }

    /// Create an LZ77 encoder with a specific compression level (1-9).
    /// The level only sets how hard the match finder looks; every level
    /// emits tokens the same decoder and the same block encoders accept.
    pub fn with_level(level: u8) -> Self {
        let (max_chain, max_lazy) = match level {
            1 => (4, 4),
            2 => (6, 6),
            3 => (32, 8),
            4 => (16, 12),
            5 => (32, 16),
            6 => (128, 32),
            7 => (256, 64),
            8 => (512, 128),
            _ => (1024, 258), // level 9
        };
        Self {
            window: Vec::new(),
            head: vec![NONE; 1 << 15],
            prev: Vec::new(),
            level,
            max_chain,
            max_lazy,
        }
    }

    /// Compress data using LZ77. Returns a vector of literals and match references.
    pub fn compress(&mut self, data: &[u8]) -> Vec<Lz77Token> {
        self.window.clear();
        self.window.extend_from_slice(data);
        self.head.fill(NONE);
        self.prev.clear();
        self.prev.resize(data.len(), NONE);

        let mut tokens = Vec::with_capacity(data.len() / 4);
        let mut pos = 0usize;
        while pos < data.len() {
            let found = self.best_match(pos);
            match found {
                Some((mut best, mut best_pos)) => {
                    // Lazy matching: if a match starting one byte later is
                    // strictly longer, the intervening byte is cheaper as a
                    // literal than the shorter match is as a reference.
                    if self.level >= 4 {
                        let lookahead = self.max_lazy.min(MAX_MATCH - best.length as usize);
                        for ahead in 1..=lookahead {
                            let probe = pos + ahead;
                            if probe + MIN_MATCH > data.len() {
                                break;
                            }
                            if let Some((later, _)) = self.best_match(probe) {
                                if later.length > best.length {
                                    for i in 0..ahead {
                                        tokens.push(Lz77Token::Literal(data[pos + i]));
                                        self.record(pos + i);
                                    }
                                    best = later;
                                    best_pos = probe;
                                    break;
                                }
                            }
                        }
                    }
                    tokens.push(Lz77Token::Match(best));
                    for i in 0..best.length as usize {
                        self.record(best_pos + i);
                    }
                    pos = best_pos + best.length as usize;
                }
                None => {
                    tokens.push(Lz77Token::Literal(data[pos]));
                    self.record(pos);
                    pos += 1;
                }
            }
        }
        tokens
    }

    /// The longest match at `pos`, capped by the chain budget. Distances
    /// are from `pos`, so a match may only reach back over recorded
    /// positions and never past the window's own start.
    fn best_match(&self, pos: usize) -> Option<(Match, usize)> {
        if pos + MIN_MATCH > self.window.len() {
            return None;
        }
        let limit = self.window.len() - pos;
        let mut best: Option<Match> = None;
        let mut chain = self.head[self.hash(pos)];
        let mut steps = 0;
        while chain != NONE && steps < self.max_chain {
            let distance = pos - chain;
            if distance == 0 || distance > MAX_DISTANCE {
                break;
            }
            let length = self.common_length(chain, pos, limit.min(MAX_MATCH));
            if length >= MIN_MATCH {
                let candidate = Match {
                    distance: distance as u16,
                    length: length as u16,
                };
                if best.is_none_or(|b| candidate.length > b.length) {
                    best = Some(candidate);
                }
            }
            chain = self.prev[chain];
            steps += 1;
        }
        best.map(|m| (m, pos))
    }

    /// Bytes shared by the windows at `a` and `b`, at most `ceiling`.
    fn common_length(&self, a: usize, b: usize, ceiling: usize) -> usize {
        let mut len = 0;
        while len < ceiling && self.window[a + len] == self.window[b + len] {
            len += 1;
        }
        len
    }

    /// Index `pos` in the hash chains. A position with fewer than three
    /// bytes left has no 3-byte prefix and is not indexed.
    fn record(&mut self, pos: usize) {
        if pos + MIN_MATCH > self.window.len() {
            return;
        }
        let h = self.hash(pos);
        self.prev[pos] = self.head[h];
        self.head[h] = pos;
    }

    /// Hash of the 3-byte prefix at `pos`.
    fn hash(&self, pos: usize) -> usize {
        let h = ((self.window[pos] as usize) << 16)
            ^ ((self.window[pos + 1] as usize) << 8)
            ^ (self.window[pos + 2] as usize);
        h & (self.head.len() - 1)
    }
}

impl Default for Lz77Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// LZ77 token (literal or match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz77Token {
    /// Literal byte.
    Literal(u8),
    /// Match reference.
    Match(Match),
}

/// LZ77 decompressor.
#[derive(Debug, Default)]
pub struct Lz77Decoder {
    /// Output buffer (acts as sliding window).
    window: Vec<u8>,
    /// Ceiling on the window, so a bomb is refused as it expands rather
    /// than after.
    cap: OutputCap,
}

impl Lz77Decoder {
    /// Create a new LZ77 decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decompress LZ77 tokens, stopping at the cap.
    pub fn decompress(&mut self, tokens: &[Lz77Token]) -> Vec<u8> {
        self.window.clear();
        self.cap = OutputCap::new(self.cap.limit());

        for token in tokens {
            match token {
                Lz77Token::Literal(byte) => {
                    if !self.add_literal(*byte) {
                        break;
                    }
                }
                Lz77Token::Match(m) => {
                    let distance = m.distance as usize;
                    let length = m.length as usize;
                    // A distance that reaches past the window is a
                    // malformed token; skip it rather than stop, so one
                    // bad reference does not discard the bytes around it.
                    if distance == 0 || distance > self.window.len() {
                        continue;
                    }
                    if !self.copy_match_checked(distance, length) {
                        break;
                    }
                }
            }
        }

        self.window.clone()
    }

    /// Copy from sliding window (used by DEFLATE decoder). False means the
    /// cap refused the whole match, and nothing was copied.
    pub fn copy_match(&mut self, distance: usize, length: usize) -> bool {
        self.copy_match_checked(distance, length)
    }

    fn copy_match_checked(&mut self, distance: usize, length: usize) -> bool {
        // Malformed/mutated DEFLATE can hand us a `distance` past the end
        // of the window; a source range past the end would then panic on
        // the bounds check. Validate before debiting the cap so a rejected
        // match leaves the byte budget untouched.
        if distance == 0 || distance > self.window.len() {
            return false;
        }
        if !self.cap.take(length as u64) {
            return false;
        }
        let start = self.window.len() - distance;
        // Three cases by overlap of the source and destination spans:
        // - `distance >= length`: non-overlapping memcpy; compiles to one memmove.
        // - `distance == 1`: every output byte is the previous one; `resize` fills.
        // - `1 < distance < length`: source range overlaps destination.
        if distance >= length {
            let end = start + length;
            self.window.extend_from_within(start..end);
        } else if distance == 1 {
            let byte = self.window[self.window.len() - 1];
            let new_len = self.window.len() + length;
            self.window.resize(new_len, byte);
        } else {
            // Overlapping: `start` is `self.window.len() - distance`, so
            // every source byte `start + i` lands inside the live region
            // (i < distance) or is the byte we just pushed (i >= distance,
            // mirroring the run). Copying the live prefix in one slice and
            // then extending in `distance`-sized chunks is what keeps the
            // branch off the hot path.
            self.window.reserve(length);
            self.window.extend_from_within(start..start + distance);
            let target = self.window.len() + length - distance;
            while self.window.len() < target {
                let cur = self.window.len();
                let take = distance.min(target - cur);
                self.window
                    .extend_from_within(cur - distance..cur - distance + take);
            }
        }
        true
    }

    /// Add a literal byte. False means the cap is spent.
    pub fn add_literal(&mut self, byte: u8) -> bool {
        if !self.cap.take(1) {
            return false;
        }
        self.window.push(byte);
        true
    }

    /// Append a slice of literal bytes in a single `extend_from_slice`. The
    /// cap is debited once for the whole run.
    pub fn add_literal_slice(&mut self, bytes: &[u8]) {
        if !self.cap.take(bytes.len() as u64) {
            return;
        }
        self.window.extend_from_slice(bytes);
    }

    /// Get the output.
    pub fn output(&self) -> &[u8] {
        &self.window
    }

    /// Set the ceiling, keeping whatever has already been emitted counted.
    pub fn set_limit(&mut self, limit: u64) {
        self.cap.set_limit(limit);
    }

    /// The ceiling in force.
    pub fn limit(&self) -> u64 {
        self.cap.limit()
    }

    /// True once the cap has refused a byte. Cheap enough for a decoder's
    /// inner loop; [`Self::bounded`] is not.
    pub fn capped(&self) -> bool {
        self.cap.capped()
    }

    /// Bytes emitted so far, and whether the cap stopped the decode.
    pub fn bounded(&self) -> super::cap::Bounded {
        if self.cap.capped() {
            super::cap::Bounded::stopped(self.window.clone(), None, self.cap.limit())
        } else {
            super::cap::Bounded::complete(self.window.clone(), None, self.cap.limit())
        }
    }

    /// [`Self::bounded`], taking the window instead of copying it.
    ///
    /// The copy is the whole inflated payload, once per deflate stream, and
    /// `zip.rs` decodes one stream per entry — so a zip paid a second
    /// full-size allocation and memcpy of everything it had just inflated. The
    /// one production caller, `DeflateDecoder::decode_bounded_with_consumed`,
    /// holds `&mut self` and has already `reset()` the decoder, so the window
    /// is owned here and nothing else can be looking at it.
    ///
    /// After this the window is empty, so a caller that needs to keep reading
    /// must not call [`Self::output`] — use this only where the stream is
    /// finished with, which is what the deflate tail is.
    pub fn take_bounded(&mut self) -> super::cap::Bounded {
        let window = core::mem::take(&mut self.window);
        if self.cap.capped() {
            super::cap::Bounded::stopped(window, None, self.cap.limit())
        } else {
            super::cap::Bounded::complete(window, None, self.cap.limit())
        }
    }

    /// Reset the decoder, keeping the ceiling.
    pub fn reset(&mut self) {
        self.window.clear();
        self.cap = OutputCap::new(self.cap.limit());
    }
}

#[cfg(all(test, feature = "lz77"))]
mod tests {
    use super::*;

    #[test]
    fn test_lz77_literal_only() {
        let mut encoder = Lz77Encoder::with_level(1);
        let data = b"abcdefgh";
        let tokens = encoder.compress(data);

        for token in &tokens {
            assert!(matches!(token, Lz77Token::Literal(_)));
        }
    }

    #[test]
    fn test_lz77_repeated_data() {
        let mut encoder = Lz77Encoder::new();
        let data = b"abcabcabcabc";
        let tokens = encoder.compress(data);

        // Should have at least one match
        assert!(tokens.iter().any(|t| matches!(t, Lz77Token::Match(_))));
    }

    #[test]
    fn test_lz77_roundtrip() {
        let mut encoder = Lz77Encoder::new();
        let mut decoder = Lz77Decoder::new();

        let data = b"Hello, World! Hello, World! Hello, World!";
        let tokens = encoder.compress(data);
        let decompressed = decoder.decompress(&tokens);

        assert_eq!(data.as_slice(), decompressed.as_slice());
    }

    #[test]
    fn test_lz77_decoder_copy_match() {
        let mut decoder = Lz77Decoder::new();

        // Add some literals
        for b in b"abc" {
            decoder.add_literal(*b);
        }

        // Copy match (distance 3, length 3) should repeat "abc"
        decoder.copy_match(3, 3);

        assert_eq!(decoder.output(), b"abcabc");
    }

    /// Malformed input can hand us a `distance` past the end of the window.
    /// The guard refuses the match instead, leaves the window intact and
    /// the cap untouched.
    #[test]
    fn test_lz77_rejects_match_past_window_end() {
        let mut decoder = Lz77Decoder::new();
        for b in b"abcde" {
            decoder.add_literal(*b);
        }
        // distance 100, length 31: `distance >= length` is true, but the
        // window is only 5 bytes long. Must return false, not panic.
        assert!(!decoder.copy_match(100, 31));
        assert_eq!(decoder.output(), b"abcde");
        // distance 0 is also nonsense (would point at the cursor itself).
        assert!(!decoder.copy_match(0, 1));
        assert_eq!(decoder.output(), b"abcde");
    }

    /// The three overlap cases of the copy are where a decode can be
    /// quietly wrong without panicking: the source and destination ranges
    /// coincide, touch, or interleave.
    #[test]
    fn overlapping_copies_replay_the_window() {
        // distance 2 >= length 2: straight copy of "ab".
        let mut d = Lz77Decoder::new();
        d.add_literal_slice(b"ab");
        assert!(d.copy_match(2, 2));
        assert_eq!(d.output(), b"abab");

        // distance 2 < length 6: "ab" then the run mirrors it.
        let mut d = Lz77Decoder::new();
        d.add_literal_slice(b"ab");
        assert!(d.copy_match(2, 6));
        assert_eq!(d.output(), b"abababab");

        // distance 1: every byte is the previous one.
        let mut d = Lz77Decoder::new();
        d.add_literal(b'x');
        assert!(d.copy_match(1, 4));
        assert_eq!(d.output(), b"xxxxx");
    }

    /// The decoder is the half every .gz/.zip payload goes through, so
    /// arbitrary (distance, length) pairs must be refused or copied, never
    /// panic — a corrupt stream is untrusted input.
    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let corpus: Vec<(&str, Vec<u8>)> = alloc::vec![
            ("empty", alloc::vec![]),
            ("odd", alloc::vec![0xFF]),
            ("zeros", alloc::vec![0; 32]),
            ("mixed", alloc::vec![3, 1, 0, 0, 200, 10, 0, 255, 255]),
        ];
        crate::fuzzkit::assert_never_panics(corpus, 2000, "lz77", |data| {
            let mut decoder = Lz77Decoder::new();
            let mut i = 0;
            while i + 3 <= data.len() {
                let distance = ((data[i] as usize) << 8 | data[i + 1] as usize) & 0x7FFF;
                let length = data[i + 2] as usize;
                let _ = decoder.copy_match(distance, length);
                let _ = decoder.add_literal(data[i]);
                i += 3;
            }
            let tokens = alloc::vec![
                Lz77Token::Literal(data.first().copied().unwrap_or(0)),
                Lz77Token::Match(Match {
                    distance: data.first().copied().unwrap_or(0) as u16,
                    length: data.get(1).copied().unwrap_or(0) as u16,
                }),
            ];
            let mut replay = Lz77Decoder::new();
            let _ = replay.decompress(&tokens);
        });
    }
}
