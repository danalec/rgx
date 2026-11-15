// SPDX-License-Identifier: Apache-2.0

//! LZ77 sliding-window match finder and token stream for DEFLATE.
//!
//! Independent reimplementation of the classic LZ77 compression scheme
//! as specified in RFC 1951 §3.2.3: a sliding window of up to 32 KiB, a
//! hash-chain match finder, and a lazy-match optimisation that defers
//! emitting a match when a longer one may start at the next position.
//!
//! # Token contract
//!
//! The encoder produces a sequence of [`Lz77Token`] values — either a
//! literal byte or a [`Match`] (distance, length).  The DEFLATE encoder
//! maps these to Huffman symbols and extra bits; the decoder inverts the
//! process via [`Lz77Decoder`].
//!
//! # Match-finding
//!
//! The hash function maps the next three bytes to a table index.  The
//! standard mode uses a simple shift-and-xor of the three bytes; the
//! Paley mode (selected via [`Lz77Encoder::with_graph_mode`]) uses a
//! Paley-graph hash from `graph_mode`, which can improve distribution on
//! some corpora.

use alloc::vec::Vec;

use super::graph_mode::{paley_hash3_bits, GraphMode};

/// Default sliding-window size (32 KiB, per RFC 1951 §3.2.7).
pub const DEFAULT_WINDOW_SIZE: usize = 32 * 1024;

/// Minimum match length.
pub const MIN_MATCH: usize = 3;

/// Maximum match length (RFC 1951 §3.2.5, length code 285).
pub const MAX_MATCH: usize = 258;

/// Maximum match distance (RFC 1951 §3.2.5, distance code 29).
pub const MAX_DISTANCE: usize = 32 * 1024;

/// A back-reference: `distance` bytes back in the output, `length` bytes long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Distance backwards from the current output position.
    pub distance: u16,
    /// Number of bytes to copy.
    pub length: u16,
}

/// LZ77 compressor with hash-chain match finding.
#[derive(Debug)]
pub struct Lz77Encoder {
    window: Vec<u8>,
    pos: usize,
    window_size: usize,
    hash_table: Vec<usize>,
    hash_chain: Vec<usize>,
    chain_head: usize,
    level: u8,
    max_chain: usize,
    max_lazy: usize,
    graph_mode: GraphMode,
}

impl Lz77Encoder {
    /// Create an encoder with default level 6.
    pub fn new() -> Self {
        Self::with_level(6)
    }

    /// Create an encoder for a specific compression level (1-9).
    ///
    /// Higher levels search deeper in the hash chain and consider more
    /// lazy-match candidates.
    pub fn with_level(level: u8) -> Self {
        let window_size = DEFAULT_WINDOW_SIZE;
        let hash_size = 1 << 15;

        let (max_chain, max_lazy) = match level {
            1 => (4, 4),
            2 => (6, 6),
            3 => (32, 8),
            4 => (16, 12),
            5 => (32, 16),
            6 => (128, 32),
            7 => (256, 64),
            8 => (512, 128),
            _ => (1024, 258),
        };

        Self {
            window: Vec::new(),
            pos: 0,
            window_size,
            hash_table: vec![0; hash_size],
            hash_chain: vec![0; window_size],
            chain_head: 0,
            level,
            max_chain,
            max_lazy,
            graph_mode: GraphMode::default(),
        }
    }

    /// Select the match-finding hash strategy.
    pub fn with_graph_mode(mut self, mode: GraphMode) -> Self {
        self.graph_mode = mode;
        self
    }

    /// Compress `data` into a sequence of literals and match references.
    pub fn compress(&mut self, data: &[u8]) -> Vec<Lz77Token> {
        let mut tokens = Vec::with_capacity(data.len() / 4);
        self.window.clear();
        self.window.extend_from_slice(data);
        self.pos = 0;

        while self.pos < data.len() {
            if let Some(m) = self.find_match() {
                let mut best_match = m;
                let mut best_pos = self.pos;

                // Lazy matching: if a longer match starts a few bytes
                // ahead, emit those bytes as literals and use the better
                // match instead.
                if self.level >= 4 {
                    for lazy in 1..=self.max_lazy.min(MAX_MATCH - m.length as usize) {
                        if self.pos + lazy + MIN_MATCH > data.len() {
                            break;
                        }
                        self.pos += lazy;
                        if let Some(lazy_match) = self.find_match() {
                            if lazy_match.length > best_match.length {
                                for i in 0..lazy {
                                    tokens.push(Lz77Token::Literal(data[best_pos + i]));
                                }
                                best_match = lazy_match;
                                best_pos = self.pos;
                                break;
                            }
                        }
                        self.pos -= lazy;
                    }
                }

                self.pos = best_pos;
                tokens.push(Lz77Token::Match(Match {
                    distance: best_match.distance,
                    length: best_match.length,
                }));

                // Index the bytes covered by the match so future positions
                // can find them.
                for i in 0..best_match.length as usize {
                    if self.pos + i + MIN_MATCH <= data.len() {
                        self.update_hash(self.pos + i);
                    }
                }
                self.pos += best_match.length as usize;
            } else {
                tokens.push(Lz77Token::Literal(data[self.pos]));
                self.update_hash(self.pos);
                self.pos += 1;
            }
        }

        tokens
    }

    /// Search the hash chain for the longest match at the current position.
    fn find_match(&self) -> Option<Match> {
        if self.pos + MIN_MATCH > self.window.len() {
            return None;
        }

        let hash = self.compute_hash(self.pos);
        let mut best_match: Option<Match> = None;
        let mut chain_len = 0;
        let mut prev = self.hash_table[hash];

        while prev != 0 && chain_len < self.max_chain {
            let dist = self.pos.saturating_sub(prev);
            if dist > MAX_DISTANCE || dist == 0 {
                break;
            }

            let len = self.match_length(prev, self.pos);
            if len >= MIN_MATCH {
                let candidate = Match {
                    distance: dist as u16,
                    length: len as u16,
                };
                match best_match {
                    Some(best) if best.length >= candidate.length => {}
                    _ => best_match = Some(candidate),
                }
            }

            prev = self.hash_chain[prev % self.window_size];
            chain_len += 1;
        }

        best_match
    }

    /// Hash the three bytes starting at `pos` into a table index.
    fn compute_hash(&self, pos: usize) -> usize {
        if pos + 2 >= self.window.len() {
            return 0;
        }
        match self.graph_mode {
            GraphMode::Standard => {
                let h = ((self.window[pos] as usize) << 16)
                    ^ ((self.window[pos + 1] as usize) << 8)
                    ^ (self.window[pos + 2] as usize);
                h % self.hash_table.len()
            }
            GraphMode::Paley => {
                paley_hash3_bits(&self.window[pos..pos + 3], 15) as usize % self.hash_table.len()
            }
        }
    }

    /// Record a position in the hash table and chain.
    fn update_hash(&mut self, pos: usize) {
        if pos + MIN_MATCH > self.window.len() {
            return;
        }
        let hash = self.compute_hash(pos);
        self.chain_head = (self.chain_head + 1) % self.window_size;
        self.hash_chain[self.chain_head] = self.hash_table[hash];
        self.hash_table[hash] = pos;
    }

    /// Length of the common prefix between two window positions.
    fn match_length(&self, pos1: usize, pos2: usize) -> usize {
        let max_len = (self.window.len() - pos2).min(MAX_MATCH);
        let mut len = 0;
        while len < max_len && self.window[pos1 + len] == self.window[pos2 + len] {
            len += 1;
        }
        len
    }
}

impl Default for Lz77Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// A single unit of LZ77 output: one literal byte or one match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz77Token {
    /// A raw byte.
    Literal(u8),
    /// A back-reference.
    Match(Match),
}

/// LZ77 decoder: expands a token stream back to bytes.
#[derive(Debug, Default)]
pub struct Lz77Decoder {
    window: Vec<u8>,
}

impl Lz77Decoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Expand a full token stream.
    pub fn decompress(&mut self, tokens: &[Lz77Token]) -> Vec<u8> {
        self.window.clear();
        for token in tokens {
            match token {
                Lz77Token::Literal(byte) => self.window.push(*byte),
                Lz77Token::Match(m) => self.copy_match(m.distance as usize, m.length as usize),
            }
        }
        self.window.clone()
    }

    /// Copy `length` bytes from `distance` back in the output (RFC 1951
    /// allows overlapping copies).
    pub fn copy_match(&mut self, distance: usize, length: usize) {
        let start = self.window.len().saturating_sub(distance);
        for i in 0..length {
            let src_pos = start + i;
            if src_pos < self.window.len() {
                self.window.push(self.window[src_pos]);
            }
        }
    }

    /// Append one literal byte.
    pub fn add_literal(&mut self, byte: u8) {
        self.window.push(byte);
    }

    /// The current output buffer.
    pub fn output(&self) -> &[u8] {
        &self.window
    }

    /// Clear the output buffer.
    pub fn reset(&mut self) {
        self.window.clear();
    }
}

#[cfg(test)]
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
        for b in b"abc" {
            decoder.add_literal(*b);
        }
        decoder.copy_match(3, 3);
        assert_eq!(decoder.output(), b"abcabc");
    }

    /// Overlapping match: distance 1, length 5 must replicate the last
    /// byte five times (RFC 1951 §3.2.5 "the last byte is used").
    #[test]
    fn lz77_overlapping_match_replicates_last_byte() {
        let mut decoder = Lz77Decoder::new();
        decoder.add_literal(b'A');
        decoder.copy_match(1, 5);
        assert_eq!(decoder.output(), b"AAAAAA");
    }

    /// Distance larger than the output length clamps to the start of the
    /// buffer (saturating_sub), producing an overlapping copy rather than
    /// a panic.
    #[test]
    fn lz77_copy_match_with_excessive_distance_clamps_to_start() {
        let mut decoder = Lz77Decoder::new();
        decoder.add_literal(b'X');
        decoder.copy_match(100, 3);
        assert_eq!(decoder.output(), b"XXXX");
    }

    /// All compression levels must round-trip.
    #[test]
    fn lz77_roundtrip_all_levels() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
        for level in 0..=9u8 {
            let mut encoder = Lz77Encoder::with_level(level);
            let mut decoder = Lz77Decoder::new();
            let tokens = encoder.compress(&data);
            let result = decoder.decompress(&tokens);
            assert_eq!(result, data, "level {level} round-trip failed");
        }
    }
}
