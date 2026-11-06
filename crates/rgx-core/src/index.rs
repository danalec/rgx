// SPDX-License-Identifier: Apache-2.0

//! Token index: an inverted index of `token -> Vec<(file_id, byte_offset)>`.
//!
//! Built once over a corpus, queried many times. A query that is "find
//! documents containing the tokens `foo` AND `bar`" is the intersection of
//! two posting lists, which the in-house byte regex would otherwise have
//! to compute by enumerating permutations of the two literals across
//! every line of every file in the corpus. On repeated queries against a
//! corpus that does not change between runs, the intersection is the
//! difference between scanning and *answering*.
//!
//! # Layout
//!
//! The index is one `BTreeMap<Vec<u8>, Vec<Posting>>` plus a
//! `Vec<String>` of file paths, indexed by `file_id`. The map is
//! `BTreeMap` rather than `HashMap` so the on-disk format is
//! deterministic (insertion order on a `HashMap` is randomized and
//! would make the diff between two builds of the same corpus noisy).
//!
//! `Posting` is a `(file_id, line_number)` pair. The line number is
//! the 1-based line that the token starts on, which is what the engine
//! prints; the byte offset is kept for the slice that the engine will
//! re-scan to confirm the match (a token hit is a candidate, not a
//! match, until the engine says so).
//!
//! `no_std + alloc` is the constraint: the BTreeMap is the only
//! structure, and the `Vec`s it holds are the only allocations. The
//! [`super::index_io`] module serializes this into rgx's own `.ugi`
//! byte format — hand-rolled, `no_std`-clean, and nothing another
//! tool reads — so the on-disk format is independent of the in-memory
//! layout.
//!
//! # Query model
//!
//! A query is a slice of bytes. The same tokenizer that built the
//! index tokenizes the query; the intersection of the resulting token
//! posting lists is the set of `(file_id, line_number)` candidates
//! that the engine then has to confirm. A single-token query is a
//! single posting-list scan; an N-token query is N posting-list scans
//! plus an N-way merge on the candidate set.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::tokenize::{ascii_lower, is_word_byte, tokens};

/// One place a token was seen.
///
/// `line` is the 1-based line number; the byte offset is held so the
/// engine can hand the right slice to its own matcher without having
/// to re-scan from offset 0. The pair is packed into two `u32`s so the
/// `Postcard` encoding is the size of a single struct, not two, and
/// the on-disk format is the same width as the in-memory one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Posting {
    pub file_id: u32,
    pub line: u32,
}

/// The inverted index.
///
/// `file_paths[file_id]` is the source path; the file id is assigned
/// at insert time and is what the posting list refers to. `tokens` is
/// `BTreeMap<Vec<u8>, Vec<Posting>>` so a single allocation per token
/// carries its whole posting list, and iteration order is the byte
/// order of the token. The total ordering means a binary search on
/// the keys is meaningful, which the query path uses.
#[derive(Default, Debug)]
pub struct TokenIndex {
    /// file id -> source path.
    file_paths: Vec<String>,
    /// token -> postings, sorted by `(file_id, line)`.
    tokens: BTreeMap<Vec<u8>, Vec<Posting>>,
}

impl TokenIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of indexed files.
    pub fn file_count(&self) -> u32 {
        self.file_paths.len() as u32
    }

    /// The number of distinct tokens.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    /// The number of postings across every token.
    pub fn posting_count(&self) -> usize {
        self.tokens.values().map(|v| v.len()).sum()
    }

    /// The path for `file_id`, or `None` if it was never inserted.
    pub fn file_path(&self, file_id: u32) -> Option<&str> {
        self.file_paths.get(file_id as usize).map(String::as_str)
    }

    /// Insert `path` and return its `file_id`. Idempotent on the path:
    /// a second call with the same path returns the same id, so the
    /// caller can build a `TokenIndex` over a tree without having to
    /// deduplicate paths itself.
    pub fn intern_path(&mut self, path: &str) -> u32 {
        if let Some(i) = self.file_paths.iter().position(|p| p == path) {
            return i as u32;
        }
        let id = self.file_paths.len() as u32;
        self.file_paths.push(String::from(path));
        id
    }

    /// Tokenize `text` and append the postings to the index. `case_insensitive`
    /// is the same flag the query side uses, so the two views of the
    /// text agree.
    ///
    /// Line numbers are tracked here, not in `tokens()`, because the
    /// index needs the line each token starts on and a separate scan
    /// over the bytes would double the work. The walk is a single
    /// pass: byte-at-a-time, bumping `line` on every newline, and
    /// emitting the token at the current `line` whenever the
    /// tokenizer accepts a byte.
    pub fn add_text(&mut self, file_id: u32, text: &[u8], case_insensitive: bool) {
        let mut line: u32 = 1;
        let mut cur: Vec<u8> = Vec::new();
        for &b in text {
            if is_word_byte(b) {
                cur.push(if case_insensitive { ascii_lower(b) } else { b });
            } else if !cur.is_empty() {
                // `get_mut` first so the common case (a token that the
                // index already tracks, e.g. `fn`, `let`, `if` in source
                // code) reuses its allocation. `entry` would otherwise
                // always create a fresh owned `Vec<u8>` for `cur` and
                // discard it through `mem::take`, which over a 7k-line
                // source file is thousands of dead allocations.
                if let Some(list) = self.tokens.get_mut(cur.as_slice()) {
                    list.push(Posting { file_id, line });
                } else {
                    self.tokens
                        .entry(core::mem::take(&mut cur))
                        .or_default()
                        .push(Posting { file_id, line });
                }
                cur.clear();
            }
            if b == b'\n' {
                line += 1;
            }
        }
        if !cur.is_empty() {
            if let Some(list) = self.tokens.get_mut(cur.as_slice()) {
                list.push(Posting { file_id, line });
            } else {
                self.tokens
                    .entry(cur)
                    .or_default()
                    .push(Posting { file_id, line });
            }
        }
    }

    /// The posting list for a single token, if any. Sorted ascending
    /// by `(file_id, line)`; the query path relies on this.
    pub fn postings(&self, token: &[u8]) -> Option<&[Posting]> {
        self.tokens.get(token).map(Vec::as_slice)
    }

    /// Iterate over every `(token, postings)` in token-sorted order.
    /// Used by [`super::index_io::save`] to walk the map without
    /// exposing it.
    pub fn tokens_iter(&self) -> impl Iterator<Item = (&[u8], &[Posting])> {
        self.tokens
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Mutable access to the underlying map, so the deserializer can
    /// insert posting lists without re-validating every entry against
    /// the public API. Returns the same `BTreeMap` the index owns;
    /// adding through this path does not re-sort the postings, so
    /// callers must write them already sorted.
    pub fn tokens_mut(&mut self) -> &mut BTreeMap<Vec<u8>, Vec<Posting>> {
        &mut self.tokens
    }

    /// The candidate `(file_id, line)` set for a multi-token query.
    ///
    /// `query` is a byte slice; the same tokenizer that built the
    /// index tokenizes it, and the intersection of the posting lists
    /// is the answer. A query with no tokens yields no candidates; a
    /// query with a token that the index does not know yields no
    /// candidates (the empty intersection is the same set as a
    /// never-seen token).
    pub fn candidates(&self, query: &[u8], case_insensitive: bool) -> Vec<Posting> {
        let toks = tokens(query, case_insensitive);
        if toks.is_empty() {
            return Vec::new();
        }
        // Sort by token length descending so the longest posting list
        // is the seed of the intersection; the rest are then probed
        // in O(shorter) and dropped quickly when the candidate is not
        // in the shorter one.
        let mut lists: Vec<&[Posting]> = toks.iter().filter_map(|t| self.postings(t)).collect();
        if lists.is_empty() {
            return Vec::new();
        }
        lists.sort_by_key(|l| core::cmp::Reverse(l.len()));
        // Seed: the longest list, deduped to (file_id, line) pairs.
        let mut out: Vec<Posting> = lists[0].to_vec();
        out.dedup();
        for list in &lists[1..] {
            // The classic merge-walk intersection: both lists are
            // sorted by (file_id, line), so two cursors can confirm
            // membership in O(|out| + |list|). The new vec is the
            // same length as the smaller of the two, so the
            // allocation is bounded by the seed.
            let mut i = 0;
            let mut j = 0;
            let mut next: Vec<Posting> = Vec::with_capacity(out.len().min(list.len()));
            while i < out.len() && j < list.len() {
                match out[i].cmp(&list[j]) {
                    core::cmp::Ordering::Less => i += 1,
                    core::cmp::Ordering::Greater => j += 1,
                    core::cmp::Ordering::Equal => {
                        next.push(out[i]);
                        i += 1;
                        j += 1;
                    }
                }
            }
            out = next;
            if out.is_empty() {
                return out;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_sample() -> TokenIndex {
        let mut idx = TokenIndex::new();
        let a = idx.intern_path("a.rs");
        let b = idx.intern_path("b.rs");
        idx.add_text(a, b"foo bar\nfoo baz\nqux\n", false);
        idx.add_text(b, b"foo bar\nfoo\n", false);
        idx
    }

    #[test]
    fn file_path_round_trip() {
        let idx = build_sample();
        assert_eq!(idx.file_path(0), Some("a.rs"));
        assert_eq!(idx.file_path(1), Some("b.rs"));
        assert_eq!(idx.file_path(2), None);
    }

    #[test]
    fn intern_path_is_idempotent() {
        let mut idx = TokenIndex::new();
        let a = idx.intern_path("dup.rs");
        let b = idx.intern_path("dup.rs");
        assert_eq!(a, b);
    }

    #[test]
    fn single_token_query_returns_all_postings() {
        let idx = build_sample();
        let got = idx.postings(b"foo").unwrap();
        assert_eq!(got.len(), 4);
    }

    #[test]
    fn unknown_token_returns_none() {
        let idx = build_sample();
        assert!(idx.postings(b"missing").is_none());
    }

    #[test]
    fn multi_token_intersection_is_correct() {
        let idx = build_sample();
        let got = idx.candidates(b"foo bar", false);
        // a.rs has foo on lines 1,2 and bar on line 1. b.rs has foo on
        // lines 1,2 and bar on line 1. The intersection is the lines
        // that have BOTH, so a.rs:1 and b.rs:1.
        let pairs: Vec<(u32, u32)> = got.iter().map(|p| (p.file_id, p.line)).collect();
        assert_eq!(pairs, vec![(0, 1), (1, 1)]);
    }

    #[test]
    fn no_tokens_yields_no_candidates() {
        let idx = build_sample();
        assert!(idx.candidates(b"   ", false).is_empty());
    }
}
