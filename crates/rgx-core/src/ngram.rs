// SPDX-License-Identifier: Apache-2.0

//! Per-file n-gram signatures: a Bloom-style filter that answers "this file
//! cannot contain the needle" before a slice is ever borrowed.
//!
//! The shape is the valvular conduit of the paper: each 4-gram is inserted
//! twice, once through a forward hash and once through a reverse one, into
//! separate halves of the signature. A query is inserted the same way and
//! tested as a **subset**: if any query bit is missing, the file cannot
//! contain the query and is skipped. The subset property is what makes the
//! filter safe -- it may only fail to prune, never prune a file that holds
//! a match -- and it is asserted in the tests below rather than assumed.
//!
//! Two widths are offered because the two operand sizes are the two the
//! paper measured: 256 bits for AVX2 and 512 for AVX-512. The choice
//! changes the prune rate, never the soundness.
//!
//! This module is the query-path form of what
//! `examples/tesla_valve.rs` evaluated in a standalone harness.

use alloc::vec::Vec;

use crate::frequency::{cost, rank};

/// Maximum possible 4-gram cost is 255^4 = 4,228,250,625 (four spaces/extended bytes).
/// Noise threshold: 4-grams above 3.8 billion are pure whitespace / identical
/// frequent runs. They saturate any filter and carry no information about
/// whether a particular file holds the needle, so they are not inserted.
pub const NOISE_THRESHOLD_COST: u64 = 3_800_000_000;

/// 256-bit (AVX2-sized) signature per file.
///
/// 4 x u64 words: 2 forward conduit words + 2 reverse collision words.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct NgramSig256 {
    w: [u64; 4],
}

impl NgramSig256 {
    /// Insert one 4-gram. Noise n-grams above [`NOISE_THRESHOLD_COST`] are
    /// skipped: they would only add bits both sides agree on.
    #[inline(always)]
    pub fn insert_ngram(&mut self, gram: &[u8]) {
        if cost(gram) > NOISE_THRESHOLD_COST {
            return;
        }
        let h1 = hash_ngram_forward(gram);
        let word_fwd = (h1 >> 6) & 1; // 0 or 1
        let bit_fwd = h1 & 63;
        self.w[word_fwd as usize] |= 1u64 << bit_fwd;

        let h2 = hash_ngram_reverse(gram);
        let word_rev = 2 + ((h2 >> 6) & 1); // 2 or 3
        let bit_rev = h2 & 63;
        self.w[word_rev as usize] |= 1u64 << bit_rev;
    }

    /// True when every bit the query set is set here too.
    ///
    /// `false` is a proof that the file cannot contain the query. `true` is
    /// not a proof that it does: this is a filter, and a false positive
    /// costs only the slice search it was meant to avoid.
    ///
    /// **An all-zero signature is unknown, not empty, and never rejects.**
    /// It is what a record whose searchable text the signer could not know
    /// carries (an archive member, an empty file, a file whose every 4-gram
    /// is noise). Treating it as "holds no bits" would prune exactly the
    /// records the filter knows nothing about -- the one lie this module
    /// must not tell -- so the zero signature stands down instead.
    #[inline(always)]
    pub fn contains_query(&self, q: &NgramSig256) -> bool {
        if self.w == [0; 4] {
            return true;
        }
        // Forward conduit test (words 0..2)
        if (self.w[0] & q.w[0]) != q.w[0] || (self.w[1] & q.w[1]) != q.w[1] {
            return false;
        }
        // Reverse loop collision test (words 2..4)
        if (self.w[2] & q.w[2]) != q.w[2] || (self.w[3] & q.w[3]) != q.w[3] {
            return false;
        }
        true
    }
}

/// 512-bit (AVX-512-sized) signature per file.
///
/// 8 x u64 words: 4 forward conduit words + 4 reverse collision words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NgramSig512 {
    w: [u64; 8],
}

impl NgramSig512 {
    /// Insert one 4-gram; see [`NgramSig256::insert_ngram`] for the noise rule.
    #[inline(always)]
    pub fn insert_ngram(&mut self, gram: &[u8]) {
        if cost(gram) > NOISE_THRESHOLD_COST {
            return;
        }
        let h1 = hash_ngram_forward(gram);
        let word_fwd = (h1 >> 6) & 3; // 0..3
        let bit_fwd = h1 & 63;
        self.w[word_fwd as usize] |= 1u64 << bit_fwd;

        let h2 = hash_ngram_reverse(gram);
        let word_rev = 4 + ((h2 >> 6) & 3); // 4..7
        let bit_rev = h2 & 63;
        self.w[word_rev as usize] |= 1u64 << bit_rev;
    }

    /// The eight words, for a caller that has to carry the signature in a
    /// fixed-size record field.
    #[inline]
    pub fn into_words(self) -> [u64; 8] {
        self.w
    }

    /// The inverse of [`Self::into_words`], for a record field that has been
    /// read back off disk.
    #[inline]
    pub fn from_words(w: [u64; 8]) -> Self {
        Self { w }
    }

    /// True when every bit the query set is set here too; see
    /// [`NgramSig256::contains_query`] for what that does and does not mean,
    /// including the all-zero signature standing down rather than rejecting.
    #[inline(always)]
    pub fn contains_query(&self, q: &NgramSig512) -> bool {
        if self.w == [0; 8] {
            return true;
        }
        for i in 0..4 {
            if (self.w[i] & q.w[i]) != q.w[i] {
                return false;
            }
        }
        for i in 4..8 {
            if (self.w[i] & q.w[i]) != q.w[i] {
                return false;
            }
        }
        true
    }
}

#[inline(always)]
fn hash_ngram_forward(gram: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in gram {
        let r = rank(b) as u64;
        h ^= (b as u64) ^ (r << 4);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[inline(always)]
fn hash_ngram_reverse(gram: &[u8]) -> u64 {
    let mut h = 0x9e3779b97f4a7c15u64;
    for &b in gram.iter().rev() {
        let r = rank(b) as u64;
        h ^= (b as u64) ^ (r << 5);
        h = h.rotate_left(11).wrapping_mul(0x517cc1b727220a95);
    }
    h
}

/// Signature of a file's bytes: every contiguous 4-gram, stride 1.
///
/// The stride of one is what buys the zero-false-negative property -- a
/// query built from a run of literal bytes is a subsequence of the file's
/// own 4-grams only if the file really contains that run.
pub fn build_sig256(bytes: &[u8]) -> NgramSig256 {
    let mut sig = NgramSig256::default();
    if bytes.len() < 4 {
        return sig;
    }
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        sig.insert_ngram(&bytes[i..i + 4]);
        i += 1;
    }
    sig
}

/// 512-bit form of [`build_sig256`].
pub fn build_sig512(bytes: &[u8]) -> NgramSig512 {
    let mut sig = NgramSig512::default();
    if bytes.len() < 4 {
        return sig;
    }
    let mut i = 0usize;
    while i + 4 <= bytes.len() {
        sig.insert_ngram(&bytes[i..i + 4]);
        i += 1;
    }
    sig
}

/// Runs of literal bytes in `pattern`, each at least `min` long.
///
/// A run is maximal: it cannot be extended either way without meeting a byte
/// the pattern does not spell literally. Runs shorter than `min` carry too
/// few n-grams to distinguish one file from another and are dropped.
fn literal_runs(bytes: &[u8], min: usize) -> Vec<&[u8]> {
    let mut chunks: Vec<&[u8]> = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        let is_lit = b.is_ascii_alphanumeric() || b == b' ' || b == b'_';
        if is_lit {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min {
                chunks.push(&bytes[s..i]);
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min {
            chunks.push(&bytes[s..bytes.len()]);
        }
    }
    chunks
}

/// Query signature of a pattern's spelling read as literal text, or `None`
/// when it spells no literal run of four bytes or more.
///
/// The spelling is NOT parsed as a regex, so this is the builder for a
/// fixed-string query or a probe. A regex pattern needs [`query_sig512`],
/// which takes the literal every match must contain; reading `abcd|efgh`
/// here would require both branches and prune a file that matches one.
///
/// `None` is the honest answer for a pattern like `[a-z]{4}`: it constrains
/// nothing about which 4-grams appear, so no signature could be built and
/// the filter must stand down. A caller that treats `None` as "never
/// matches" loses files, which is the one thing this filter must not do.
pub fn build_query256(pattern: &str) -> Option<NgramSig256> {
    let bytes = pattern.as_bytes();
    let chunks = literal_runs(bytes, 4);
    if chunks.is_empty() {
        return None;
    }
    let mut sig = NgramSig256::default();
    let mut inserted = 0;
    for chunk in chunks {
        let mut i = 0usize;
        while i + 4 <= chunk.len() {
            sig.insert_ngram(&chunk[i..i + 4]);
            inserted += 1;
            i += 1;
        }
    }
    if inserted == 0 {
        None
    } else {
        Some(sig)
    }
}

/// 512-bit form of [`build_query256`].
pub fn build_query512(pattern: &str) -> Option<NgramSig512> {
    let bytes = pattern.as_bytes();
    let chunks = literal_runs(bytes, 4);
    if chunks.is_empty() {
        return None;
    }
    let mut sig = NgramSig512::default();
    let mut inserted = 0;
    for chunk in chunks {
        let mut i = 0usize;
        while i + 4 <= chunk.len() {
            sig.insert_ngram(&chunk[i..i + 4]);
            inserted += 1;
            i += 1;
        }
    }
    if inserted == 0 {
        None
    } else {
        Some(sig)
    }
}

/// The signature a stored record carries: [`build_sig512`] over the bytes
/// the searcher will actually see.
///
/// `search_slice` settles a byte-order mark and decodes UTF-16 before
/// matching (`searcher::Config::bom_sniffing`), so a BOM-marked file is
/// searched as its decoded text. Signing its raw bytes would build a
/// signature that does not cover the text the query runs on, and the filter
/// would then prune a file that matches. An unmarked file is signed as it
/// stands, which is what the searcher sees too.
pub fn build_stored_sig512(content: &[u8]) -> NgramSig512 {
    match crate::encoding::sniff(content) {
        Some(bom) => build_sig512(&crate::encoding::decode(bom, content)),
        None => build_sig512(content),
    }
}

/// Whether a search over the record's own bytes is covered by its stored
/// signature -- the library's pack search, whose haystack is exactly the
/// bytes the raw signature was built over. A rollup (the OR with every
/// adapter unit) covers them too; one signed under a foreign extraction
/// fingerprint is stood down anyway, conservatively, because the caller
/// cannot say what units it would have produced.
#[inline]
pub fn covered_raw_bytes(sig_covers_adapter: bool, rollup_ok: bool) -> bool {
    rollup_ok || !sig_covers_adapter
}

/// Whether a search that runs the adapter pipeline over the record
/// (`run_tv_query`) is covered by its stored signature. An unclaimed file
/// is searched as its own bytes and any signature covers those; a claimed
/// one is searched as the pipeline's units, which only a rollup flagged
/// `SIG_COVERS_ADAPTER` under a matching extraction fingerprint covers,
/// because the units a different context would extract are not the units
/// the signature OR'd.
#[inline]
pub fn covered_pipeline_units(claimed: bool, sig_covers_adapter: bool, rollup_ok: bool) -> bool {
    !claimed || (sig_covers_adapter && rollup_ok)
}

/// One record-level rule for every n-gram filter site: with `covered` the
/// site's own coverage answer (see [`covered_raw_bytes`] /
/// [`covered_pipeline_units`]), a signature missing a bit the query's holds
/// is proof the record cannot match and the record is rejected before its
/// bytes are read. The all-zero signature (an un-analysed record) stands
/// the filter down inside [`NgramSig512::contains_query`].
///
/// FNR=0 is the contract: this may over-report and must never lose a
/// match, so every doubt is resolved at the `covered` gate before this
/// predicate is asked anything.
#[inline]
pub fn may_reject(ngram: &[u64; 8], covered: bool, query: &NgramSig512) -> bool {
    covered && !NgramSig512::from_words(*ngram).contains_query(query)
}

/// Query signature of a pattern, from the literal every match must contain,
/// or `None` when nothing usable is known.
///
/// The literal comes from [`crate::required::anywhere`] -- the longest
/// literal that EVERY match contains -- not from the pattern's spelling.
/// A spelling-based reading is wrong the moment the pattern is a regex:
/// `abcd|efgh` matches a file that holds only `efgh`, so a query requiring
/// both runs would prune a file that matches, and `abcd*` matches `abc`, so
/// a query requiring the 4-gram `abcd` would do the same. Only the analysis
/// answers "what does every match contain", and that is the only claim
/// strong enough to reject a file on.
///
/// `None` means "do not filter", never "nothing matches": a pattern with no
/// required literal of four bytes (`[a-z]{4}`, `a|b`), a folded literal
/// (`(?i)needle` -- the stored signature is case-sensitive and would prune
/// the `Needle` spelling), or a parse the analysis cannot read all stand
/// the filter down. A caller that treats `None` as "no match" loses files,
/// which is the one thing this filter must not do.
///
/// `case_insensitive` is the builder-side fold (rgx's `-i`/smart-case). It
/// is handed to the parser as a flag so a folded literal is marked and
/// declined exactly as an in-pattern `(?i)` one is.
pub fn query_sig512(pattern: &str, case_insensitive: bool) -> Option<NgramSig512> {
    let parsed = crate::syntax::parse_with(
        pattern.as_bytes(),
        crate::syntax::Flags {
            case_insensitive,
            ..crate::syntax::Flags::default()
        },
    )
    .ok()?;
    let r = crate::required::anywhere(&parsed.ast)?;
    if r.caseless {
        return None;
    }
    if r.bytes.len() < 4 {
        return None;
    }
    let sig = build_sig512(&r.bytes);
    if sig.w == [0; 8] {
        // Every 4-gram of the literal is noise, so the signature asserts
        // nothing; `None` is the honest spelling of a query that would
        // admit every file anyway.
        return None;
    }
    Some(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole filter rests on: a file that contains the
    /// query's literal run always passes. Without this the filter prunes
    /// real matches and the search lies by omission. Each probe is one the
    /// haystack actually holds -- a probe a file does not hold is the other
    /// test's subject, not this one's.
    #[test]
    fn a_file_holding_the_query_always_passes_the_filter() {
        let cases: &[(&[u8], &[&str])] = &[
            (
                b"prefix pub fn compute_totals suffix",
                &["pub fn", "prefix", "totals", "compute_totals"],
            ),
            (b"hello needle world", &["needle", "hello", "world"]),
            (b"aaaaaaaaaa pub fn short", &["pub fn", "aaaa", "short"]),
            (
                b"one\ntwo\nthree\nfour\n",
                &["three", "four", "three\nfour"],
            ),
        ];
        for (hay, probes) in cases {
            for probe in probes.iter() {
                let q = build_query256(probe).expect("probe has a literal run");
                assert!(
                    build_sig256(hay).contains_query(&q),
                    "{probe:?} must not be pruned from {hay:?}"
                );
                let q5 = build_query512(probe).expect("probe has a literal run");
                assert!(
                    build_sig512(hay).contains_query(&q5),
                    "{probe:?} must not be pruned from {hay:?} at 512 bits"
                );
            }
        }
    }

    /// A file that does not hold the query's literal run is usually pruned.
    /// "Usually" is all a Bloom filter promises -- the point of the test is
    /// that it is not never.
    #[test]
    fn a_file_without_the_query_is_pruned() {
        let hay = b"completely unrelated content with no such run at all";
        let q = build_query256("pub fn").expect("probe has a literal run");
        assert!(!build_sig256(hay).contains_query(&q));
        let q5 = build_query512("pub fn").expect("probe has a literal run");
        assert!(!build_sig512(hay).contains_query(&q5));
    }

    /// A pattern with no literal run of four bytes constrains no 4-gram, so
    /// the builder declines rather than returning a signature that would
    /// prune everything.
    #[test]
    fn a_pattern_with_no_literal_run_declines_to_filter() {
        assert!(build_query256("[a-z]{4}").is_none());
        assert!(build_query512("").is_none());
        assert!(build_query256("ab|cd").is_none());
    }

    /// The two widths must not disagree about soundness: anything 256 bits
    /// admits, 512 bits admits too.
    #[test]
    fn the_wider_signature_prunes_no_more_than_the_narrower() {
        let hay = b"the quick brown fox jumps over the lazy dog";
        for probe in ["quick", "brown fox", "lazy dog", "the quick"] {
            let q256 = build_query256(probe).expect("probe has a literal run");
            let q512 = build_query512(probe).expect("probe has a literal run");
            if build_sig256(hay).contains_query(&q256) {
                assert!(
                    build_sig512(hay).contains_query(&q512),
                    "{probe:?} admitted at 256 must be admitted at 512"
                );
            }
        }
    }

    /// The zero signature is what a record whose searchable text the signer
    /// could not know carries (an archive member, an empty file). It must
    /// never reject: the filter knows nothing about those bytes, and
    /// pruning them would drop matches by omission.
    #[test]
    fn a_zero_signature_never_rejects() {
        let q5 = build_query512("pub fn").expect("probe has a literal run");
        assert!(NgramSig512::default().contains_query(&q5));
        let q2 = build_query256("pub fn").expect("probe has a literal run");
        assert!(NgramSig256::default().contains_query(&q2));
    }

    /// The stored signature covers the text the SEARCHER sees. `search_slice`
    /// settles a byte-order mark and decodes UTF-16 before matching, so
    /// signing the raw bytes of a marked file would build a signature the
    /// query cannot pass on a file that matches.
    #[test]
    fn the_stored_signature_covers_what_the_searcher_sees() {
        let q = query_sig512("needle", false).expect("literal engages");
        // UTF-16LE under a mark: the matcher sees "xx needle yy".
        let mut raw = vec![0xff, 0xfe];
        for b in b"xx needle yy" {
            raw.push(*b);
            raw.push(0x00);
        }
        assert!(
            build_stored_sig512(&raw).contains_query(&q),
            "the decoded text holds the literal, so the stored signature must too"
        );
        // The raw signature rejects -- which is the defect the decode rule
        // exists to prevent. Deterministic: the hashes are fixed.
        assert!(
            !build_sig512(&raw).contains_query(&q),
            "the raw UTF-16 bytes hold no ASCII run; if this passes, the \
             premise of the rule above is wrong"
        );
        // A UTF-8 mark is stripped; the text after it is what is signed.
        let mut utf8 = vec![0xef, 0xbb, 0xbf];
        utf8.extend_from_slice(b"xx needle yy");
        assert!(build_stored_sig512(&utf8).contains_query(&q));
        // Unmarked content is signed as it stands.
        assert!(build_stored_sig512(b"xx needle yy").contains_query(&q));
    }

    /// **The property the query filter is judged by: it never prunes a file
    /// that matches.** Each case is (pattern, case fold, bytes of a file the
    /// pattern matches), built to break a spelling-based reading of the
    /// pattern -- an alternation whose branches differ, a quantified byte, a
    /// folded spelling -- because those are the shapes where requiring the
    /// pattern's own runs would reject a real match. Standing down passes
    /// trivially; the test after this one pins where the filter must engage
    /// so this grid is never vacuous.
    #[test]
    fn the_query_filter_never_prunes_a_file_that_matches() {
        let cases: &[(&str, bool, &[u8])] = &[
            // Alternation: each file holds one branch only.
            ("abcd|efgh", false, b"zz efgh yy"),
            ("abcd|efgh", false, b"zz abcd yy"),
            // Alternation where every match shares a tail. The tail is
            // required; the branches' own runs are not.
            ("xabcde|yabcde", false, b"zz xabcde yy"),
            ("xabcde|yabcde", false, b"zz yabcde yy"),
            ("foo(barx|bazy)quxw", false, b"zz foobarxquxw yy"),
            ("foo(barx|bazy)quxw", false, b"zz foobazquxw yy"),
            // A quantified byte is optional; requiring it would prune.
            ("abcd*", false, b"zz abc yy"),
            ("abcd?efgh", false, b"zz abcefgh yy"),
            // Folded literals match every spelling.
            ("(?i)needle", false, b"xx NEEDLE yy"),
            ("(?i)needle", false, b"xx Needle yy"),
            ("needle", true, b"xx NEEDLE yy"),
            ("(?i)abc5def", false, b"xx ABC5DEF yy"),
            // Anchors constrain position, not content.
            ("^abcde", false, b"abcde\nrest\n"),
            // A class in the middle splits the spelling into runs; the tail
            // is what every match holds.
            ("ab[0-9]cdefgh", false, b"ab3cdefgh"),
            // Bounded repeat: the unrolled spelling holds, one `a` per
            // iteration, and so does a file the pattern matches.
            ("a{2}bcdef", false, b"zz aabcdef yy"),
            // Plain literal: the case that must engage the filter at all.
            (
                "pub fn compute_totals",
                false,
                b"prefix pub fn compute_totals suffix",
            ),
        ];
        for (pat, ci, hay) in cases {
            let Some(q) = query_sig512(pat, *ci) else {
                continue; // standing down is always sound
            };
            assert!(
                build_stored_sig512(hay).contains_query(&q),
                "pattern {pat:?} (case_insensitive={ci}) pruned a file it matches: {hay:?}"
            );
        }
    }

    /// The grid above is only a test if the filter engages where it can and
    /// stands down where it must: a builder returning `None` for everything
    /// would pass it silently, and one returning `Some` for a folded or
    /// branch-split pattern would prune matches the grid exists to protect.
    #[test]
    fn the_query_builder_engages_where_it_must_and_stands_down_where_it_must() {
        for (pat, ci) in [
            ("pub fn compute_totals", false),
            ("abcd?efgh", false),
            ("xabcde|yabcde", false),
            ("ab[0-9]cdefgh", false),
            ("^abcde", false),
            ("a{2}bcdef", false),
            ("foo(barx|bazy)quxw", false),
        ] {
            assert!(
                query_sig512(pat, ci).is_some(),
                "{pat:?} must engage the filter"
            );
        }
        for (pat, ci) in [
            // No literal of four bytes every match holds.
            ("abcd|efgh", false),
            ("[a-z]{4}", false),
            ("a|b", false),
            ("", false),
            // Folded: the stored signature is case-sensitive.
            ("needle", true),
            ("(?i)needle", false),
        ] {
            assert!(
                query_sig512(pat, ci).is_none(),
                "{pat:?} (case_insensitive={ci}) must stand the filter down"
            );
        }
    }
}
