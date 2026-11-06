// SPDX-License-Identifier: Apache-2.0

//! Regression tests for two out-of-bounds panics in the media adapter, both
//! reachable from a tiny crafted file, both aborting the process rather than
//! degrading to a `Bail`.
//!
//! `walk_sfnt`'s TrueType-collection loop read the offset table BEFORE the
//! guard that was supposed to cover it, so a 12-byte `ttcf` file indexed
//! `data[12..16]` on a 12-byte slice.
//!
//! `Mobi::extract` read the fullname and EXTH fields at FIXED offsets inside
//! the MOBI header while only validating the file's own declared header length,
//! which is a u32 with no lower bound -- so a ~94-byte book with that length
//! set to zero passed the check and then indexed `r0[144..148]` on a 36-byte
//! record.
//!
//! Both are shaped here rather than described, because "a short file" is not a
//! reproducible input and the whole point is that the exact bytes matter.

use super::*;
#[cfg(feature = "font")]
use alloc::vec::Vec;

/// 12 bytes: `ttcf`, a version, and `numFonts = 1` with no offset table at all.
/// The old loop read `data[12..16]` immediately.
#[cfg(feature = "font")]
#[test]
fn a_ttcf_with_no_offset_table_does_not_panic() {
    let mut f = Vec::new();
    f.extend_from_slice(b"ttcf"); // 0..4   tag
    f.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // 4..8   version
    f.extend_from_slice(&1u32.to_be_bytes()); // 8..12  numFonts = 1
    assert_eq!(f.len(), 12, "the whole input is the trigger");

    let mut out = String::new();
    let _ = walk_sfnt(&f, 0, &mut out, 0);
}

/// The same, one font entry long but pointing past the end.
#[cfg(feature = "font")]
#[test]
fn a_ttcf_whose_offset_table_is_truncated_does_not_panic() {
    let mut f = Vec::new();
    f.extend_from_slice(b"ttcf");
    f.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    f.extend_from_slice(&4u32.to_be_bytes()); // claim 4 fonts
    f.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes()); // one entry, absurd
    assert_eq!(f.len(), 16);

    let mut out = String::new();
    let _ = walk_sfnt(&f, 0, &mut out, 0);
}

/// ~94 bytes: a PalmDOC header whose `numRecords`, `rec0` and `rec1` all pass
/// their guards, whose record 0 starts with `MOBI`, and whose declared MOBI
/// header length is **0** so the declared-length guard is satisfied.
#[cfg(feature = "mobi")]
#[test]
fn a_mobi_record_with_a_zero_declared_header_length_does_not_panic() {
    let mut d = vec![0u8; 94];

    // PalmDOC database header: name (32), attributes (2), version (2), ...,
    // numRecords at 76.
    d[76..78].copy_from_slice(&2u16.to_be_bytes()); // numRecords = 2
                                                    // Record info entries start at 78: rec0 offset, rec0 attributes, rec1 ...
    d[78..82].copy_from_slice(&100u32.to_be_bytes()); // rec0 = 100
    d[86..90].copy_from_slice(&136u32.to_be_bytes()); // rec1 = 136
                                                      // "record 0 out of range" checks `rec0 + 36 <= min(rec1, len)`; with
                                                      // rec0 = 100 that needs 136 <= len, so the file has to be at least that
                                                      // long. Pad it out.
    let mut d = {
        let mut v = d;
        v.resize(200, 0);
        v
    };
    d[100 + 16..100 + 20].copy_from_slice(b"MOBI");
    d[100 + 20..100 + 24].copy_from_slice(&0u32.to_be_bytes()); // header_len = 0

    // rec1 = 136 means record 0 spans 100..136, which is 36 bytes -- the
    // minimum the existing guard allows.
    // The assertion is that this RETURNS. A `Bail` is the right answer for
    // every one of these inputs; an abort is the bug.
    assert!(
        Mobi.extract(&d, "book.mobi").is_err(),
        "a crafted book should decline, not abort"
    );
}
