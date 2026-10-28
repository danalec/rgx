// SPDX-License-Identifier: Apache-2.0

//! On-disk format for the token index, written to `.ugi` files by
//! `rgx --index-build <dir>` and read back by `rgx --index <dir>`.
//!
//! # Format
//!
//! The file is a single self-describing byte stream:
//!
//! ```text
//! +---------------------------+
//! | 7-byte magic "RGXIDX\0"   |
//! | 1-byte version (currently 0x01)                  |
//! | 1-byte flags (bit 0 = case_insensitive)         |
//! | 4-byte LE file count                            |
//! | 4-byte LE token count                           |
//! | 4-byte LE posting count                         |
//! +---------------------------+
//! | file table: `file_count` length-prefixed UTF-8  |
//! | paths, each as 4-byte LE length + bytes          |
//! +---------------------------+
//! | token table: `token_count` entries               |
//! |   4-byte LE token length                         |
//! |   N bytes of token                               |
//! |   4-byte LE posting count                        |
//! |   `posting count` * 8 bytes (file_id:u32, line:u32) |
//! +---------------------------+
//! ```
//!
//! The format is **not** the upstream `ugrep` `.ugi` format, and the
//! flag names are not the whole story either. The CLI accepts
//! `--index-build`, `--index` and `--index-store` (`src/main.rs`); only
//! the `--index` spelling is ugrep's, `--build-index` and `--tokenize` do
//! not exist here. The on-disk file belongs to rgx and is loaded only by
//! rgx. A future commit can
//!
//! # Allocations
//!
//! `save` allocates one `Vec<u8>` and writes into it. `load`
//! allocates the index and every posting list in a single read;
//! a memory-mapped loader is the next step but is not in scope for
//! the first cut, where the corpus is small enough that
//! `read_to_end` is the right primitive.

extern crate alloc;

use alloc::vec::Vec;

use super::index::{Posting, TokenIndex};

const MAGIC: &[u8; 7] = b"RGXIDX\0";
const VERSION: u8 = 0x01;
/// Bit 0 of the flags byte. 1 = index was built case-insensitive, so
/// queries with `case_insensitive: true` will hit the index and
/// queries with `case_insensitive: false` should be rejected.
const FLAG_CASE_INSENSITIVE: u8 = 0x01;

/// Write `index` to `out` in the rgx `.ugi` format.
pub fn save(index: &TokenIndex, case_insensitive: bool, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(if case_insensitive {
        FLAG_CASE_INSENSITIVE
    } else {
        0
    });
    out.extend_from_slice(&index.file_count().to_le_bytes());
    out.extend_from_slice(&(index.token_count() as u32).to_le_bytes());
    out.extend_from_slice(&(index.posting_count() as u32).to_le_bytes());
    for path in (0..index.file_count()).filter_map(|i| index.file_path(i)) {
        let bytes = path.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    for (tok, postings) in index_token_iter(index) {
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(tok);
        out.extend_from_slice(&(postings.len() as u32).to_le_bytes());
        for p in postings {
            out.extend_from_slice(&p.file_id.to_le_bytes());
            out.extend_from_slice(&p.line.to_le_bytes());
        }
    }
}

/// Read the bytes of a `.ugi` file back into a `TokenIndex`.
///
/// Returns an `Err(&'static str)` describing the first inconsistency
/// (bad magic, bad version, truncated length, etc.). The string is
/// a static diagnostic, not a heap allocation.
pub fn load(bytes: &[u8], case_insensitive: bool) -> Result<TokenIndex, &'static str> {
    let mut p = 0;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], &'static str> {
        if *p + n > bytes.len() {
            return Err("truncated header");
        }
        let out = &bytes[*p..*p + n];
        *p += n;
        Ok(out)
    };
    let take_u32 = |p: &mut usize| -> Result<u32, &'static str> {
        let b = take(p, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    if take(&mut p, MAGIC.len())? != MAGIC {
        return Err("not an rgx index file (magic mismatch)");
    }
    let version = take(&mut p, 1)?[0];
    if version != VERSION {
        return Err("unsupported index version");
    }
    let flags = take(&mut p, 1)?[0];
    let built_ci = (flags & FLAG_CASE_INSENSITIVE) != 0;
    if built_ci != case_insensitive {
        return Err(if built_ci {
            "index was built case-insensitive; rerun with -i"
        } else {
            "index was built case-sensitive; rerun without -i"
        });
    }
    let file_count = take_u32(&mut p)? as usize;
    let token_count = take_u32(&mut p)? as usize;
    let _posting_count = take_u32(&mut p)?;

    let mut index = TokenIndex::new();
    for _ in 0..file_count {
        let n = take_u32(&mut p)? as usize;
        let path_bytes = take(&mut p, n)?;
        let path = core::str::from_utf8(path_bytes).map_err(|_| "non-utf8 file path")?;
        index.intern_path(path);
    }
    for _ in 0..token_count {
        let n = take_u32(&mut p)? as usize;
        let tok = take(&mut p, n)?.to_vec();
        let post_n = take_u32(&mut p)? as usize;
        // The reservation is clamped to what the remaining bytes can hold:
        // a posting is 8 bytes on the disk, and a corrupted count must
        // fail in the read, not in the allocation.
        let mut postings = Vec::with_capacity(post_n.min((bytes.len() - p) / 8));
        for _ in 0..post_n {
            let file_id = take_u32(&mut p)?;
            let line = take_u32(&mut p)?;
            postings.push(Posting { file_id, line });
        }
        index.tokens_mut().insert(tok, postings);
    }
    Ok(index)
}

/// Iterate over `(token, &postings)` in token-sorted order. The
/// `TokenIndex` keeps the map private; this helper is the single
/// read-only accessor the format needs.
fn index_token_iter(index: &TokenIndex) -> impl Iterator<Item = (&[u8], &[Posting])> {
    index.tokens_iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::TokenIndex;

    fn round_trip(ci: bool) {
        let mut idx = TokenIndex::new();
        let a = idx.intern_path("alpha.txt");
        let b = idx.intern_path("beta.txt");
        idx.add_text(a, b"foo bar\nfoo baz\nqux\n", ci);
        idx.add_text(b, b"foo bar\nfoo\n", ci);
        let mut buf = Vec::new();
        save(&idx, ci, &mut buf);
        let back = load(&buf, ci).expect("round-trip");
        assert_eq!(back.file_count(), 2);
        assert_eq!(back.token_count(), idx.token_count());
        assert_eq!(back.posting_count(), idx.posting_count());
        for tok in [b"foo", b"bar", b"baz", b"qux"] {
            let a = idx.postings(tok).unwrap_or(&[]);
            let b = back.postings(tok).unwrap_or(&[]);
            assert_eq!(a, b, "postings for {tok:?} diverged");
        }
    }

    #[test]
    fn save_load_round_trip_case_sensitive() {
        round_trip(false);
    }

    #[test]
    fn save_load_round_trip_case_insensitive() {
        round_trip(true);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = b"NOTRGI\0\x01\x00".to_vec();
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert!(load(&buf, false).is_err());
    }

    #[test]
    fn ci_mismatch_is_rejected() {
        let mut idx = TokenIndex::new();
        idx.intern_path("a");
        idx.add_text(0, b"foo", false);
        let mut buf = Vec::new();
        save(&idx, false, &mut buf);
        assert!(load(&buf, true).is_err());
    }
}
