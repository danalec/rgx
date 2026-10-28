// SPDX-License-Identifier: Apache-2.0

//! Unicode tokenizer for the token index.
//!
//! The token index in [`super::index`] keys on whole tokens, not bytes; a
//! query like `foo bar` is "documents that contain `foo` AND `bar` near each
//! other", which the in-house byte regex would have to do by enumerating
//! every permutation. The index makes the common case a single
//! `O(tokens_in_query)` posting-list intersect.
//!
//! # What is a token
//!
//! A token is the longest run of bytes that is *wordy*. The set of wordy
//! bytes is the ASCII letters, digits, underscore, and the UTF-8 lead bytes
//! that begin a non-ASCII character (so the multi-byte encodings of `é`,
//! `日本`, etc. stay together and do not get split on their continuation
//! bytes). A byte that is none of those ends a token.
//!
//! This is the same shape ugrep's default tokenization produces, which is
//! why the CLI flags in `src/main.rs` that pass through to it are
//! ugrep-compatible (`--build-index` / `--index`). The `unicode-segmentation`
//! crate is the more careful option; it would split the same text on a
//! larger set of boundaries, including the inside of certain CJK runs.
//! That is a future option, gated by a future flag, not the default.
//!
//! # `no_std`
//!
//! Tokenize a byte slice, lowercase on the way out when `case_insensitive`
//! is set, and otherwise copy the bytes verbatim. `to_lowercase` is the
//! ASCII fast path; non-ASCII characters are returned as-is, which is
//! what ugrep's `--tokenize=letter` does and what the index's
//! case-insensitive query mode needs to match.

use alloc::vec::Vec;

/// Whether a single byte starts or continues a wordy run.
#[inline]
pub fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// Lowercase an ASCII byte. The non-ASCII bytes are returned unchanged;
/// Unicode case folding is a future option.
#[inline]
pub fn ascii_lower(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// Tokenize `text` into a fresh `Vec<Vec<u8>>`. Consecutive wordy bytes
/// land in the same token; a non-wordy byte ends one and starts the
/// next on the following wordy byte. Empty tokens (runs of non-wordy
/// bytes) are not emitted.
///
/// When `case_insensitive` is true, every byte of every token is run
/// through [`ascii_lower`]. The non-ASCII case is preserved byte-for-byte,
/// which is the same trade-off ugrep's `--tokenize=letter` makes; a
/// case-folded index for non-ASCII text would need a different
/// normalization.
pub fn tokens(text: &[u8], case_insensitive: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for &b in text {
        if is_word_byte(b) {
            cur.push(if case_insensitive { ascii_lower(b) } else { b });
        } else if !cur.is_empty() {
            // Move avoids a clone + a re-allocation next iteration. The
            // vec is empty after, so the next wordy run starts a fresh
            // buffer with the right capacity (the previous cap).
            out.push(core::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Same as [`tokens`] but flattens into a `Vec<u8>` of token bytes
/// separated by `0x1f` (the ASCII unit-separator, which cannot appear
/// in a token because the tokenizer only emits wordy bytes). One
/// allocation, one pass.
///
/// The previous shape routed through `Vec<Vec<u8>>` first, which allocated
/// a fresh `Vec<u8>` per token (plus an outer Vec) and then copied every
/// token a second time into the joined output. For a 7k-line source file
/// that is ~2,000 intermediate Vecs, all of which exist solely to be
/// concatenated. The new shape writes directly into `out`.
pub fn tokens_join(text: &[u8], case_insensitive: bool) -> Vec<u8> {
    // Pre-count total length so the output is reserved in a single
    // allocation. Wordy runs are bounded by `len(text)`, plus one
    // separator per token. A first pass over the bytes is cheap
    // (no allocations) and saves a doubling sequence inside `extend`.
    let mut total = 0usize;
    let mut wordy_run = false;
    for &b in text {
        if is_word_byte(b) {
            total += 1;
            wordy_run = true;
        } else if wordy_run {
            total += 1;
            wordy_run = false;
        }
    }
    if wordy_run {
        total += 1;
    }
    let mut out = Vec::with_capacity(total);
    for &b in text {
        if is_word_byte(b) {
            out.push(if case_insensitive { ascii_lower(b) } else { b });
        } else if !out.is_empty() && out.last() != Some(&0x1f) {
            out.push(0x1f);
        }
    }
    // Match the legacy contract: every emitted token, including the
    // last, is followed by a separator. A trailing separator is what the
    // on-disk ugi format expects when slicing by 0x1f.
    if !out.is_empty() && out.last() != Some(&0x1f) {
        out.push(0x1f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_words_split_on_punct() {
        assert_eq!(
            tokens(b"foo, bar; baz", false),
            vec![b"foo".to_vec(), b"bar".to_vec(), b"baz".to_vec()]
        );
    }

    #[test]
    fn underscores_and_digits_are_wordy() {
        assert_eq!(
            tokens(b"foo_bar123 baz", false),
            vec![b"foo_bar123".to_vec(), b"baz".to_vec()]
        );
    }

    #[test]
    fn utf8_runs_stay_together() {
        let toks = tokens(b"caf\xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC", false);
        assert_eq!(
            toks,
            vec![
                b"caf\xc3\xa9".to_vec(),
                b"\xe6\x97\xa5\xe6\x9c\xac".to_vec()
            ]
        );
    }

    #[test]
    fn case_insensitive_lowers_ascii_only() {
        let toks = tokens(b"FOO caf\xC3\xA9 BAR", true);
        assert_eq!(
            toks,
            vec![b"foo".to_vec(), b"caf\xc3\xa9".to_vec(), b"bar".to_vec()]
        );
    }

    #[test]
    fn empty_text_yields_no_tokens() {
        assert!(tokens(b"", false).is_empty());
        assert!(tokens(b"   ", false).is_empty());
        assert!(tokens(b"---", false).is_empty());
    }

    #[test]
    fn tokens_join_inserts_unit_separators() {
        let joined = tokens_join(b"foo bar baz", false);
        assert_eq!(joined, b"foo\x1fbar\x1fbaz\x1f");
    }
}
