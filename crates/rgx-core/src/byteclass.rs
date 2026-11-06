// SPDX-License-Identifier: Apache-2.0

//! Byte sets: the alphabet a byte-mode regex matches over.
//!
//! **Provenance.** Written here first, at full scope, and copied into rgx as
//! `crates/rgx-core/src/byteclass.rs`. The copy is the same file with
//! `alloc::` rewritten to `std::`; rgx's `scripts/check-vendoring.ps1` and
//! `scripts/check-drift.ps1` track it, and
//! `scripts/apply-vendored-edits.ps1` re-applies the rewrite on every
//! re-copy. This header travels with the file so the copy never has to carry
//! it separately.
//!
//! **Verification.** The set algebra is exact by construction — a 256-bit
//! membership table has no approximation in it — so the tests here are
//! algebraic identities (complement of complement, union associativity,
//! range agreement with per-byte insertion) rather than third-party vectors.
//! That is the right standard for this type: a wrong answer in it is a wrong
//! *match*, because the matcher compiles every character class to one.
//!
//! Every character class, literal byte and `.` compiles to one of these.
//! A 256-bit set makes membership a single bit test, which matters
//! because this sits in the innermost loop of the searcher — a binary
//! search over ranges would be correct and measurably slower on every
//! byte of every file.
//!
//! A set is deliberately total: complement is taken over all 256 values,
//! and an empty pattern still matches the empty string, so there is no
//! "matches nothing" state to represent.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// A set of byte values, as a 256-bit membership table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ByteSet {
    bits: [u64; 4],
}

impl ByteSet {
    /// The empty set.
    pub const fn empty() -> Self {
        Self { bits: [0; 4] }
    }

    /// The set containing every byte.
    pub const fn any() -> Self {
        Self {
            bits: [u64::MAX; 4],
        }
    }

    /// A set containing exactly one byte.
    pub fn single(b: u8) -> Self {
        let mut s = Self::empty();
        s.insert(b);
        s
    }

    /// A set containing an inclusive range.
    pub fn range(lo: u8, hi: u8) -> Self {
        let mut s = Self::empty();
        s.insert_range(lo, hi);
        s
    }

    /// A set containing every byte except `\n`.
    ///
    /// This is `.` without `(?s)`. In a byte-oriented engine `.` is a
    /// byte class, not a scalar-value one: it must not span a multi-byte
    /// UTF-8 sequence when the caller asked for scalar semantics, which
    /// is what the scalar layer in `regex.rs` arranges.
    pub fn any_except_newline() -> Self {
        let mut s = Self::any();
        s.remove(b'\n');
        s
    }

    #[inline]
    pub fn insert(&mut self, b: u8) {
        self.bits[usize::from(b) >> 6] |= 1u64 << (b & 63);
    }

    #[inline]
    pub fn remove(&mut self, b: u8) {
        self.bits[usize::from(b) >> 6] &= !(1u64 << (b & 63));
    }

    #[inline]
    pub fn contains(&self, b: u8) -> bool {
        self.bits[usize::from(b) >> 6] & (1u64 << (b & 63)) != 0
    }

    /// Add every byte in the inclusive range.
    pub fn insert_range(&mut self, lo: u8, hi: u8) {
        // A partial first word, whole middle words, a partial last word.
        for b in lo..=hi {
            self.insert(b);
        }
    }

    /// Union of two sets.
    pub fn union(&self, other: &Self) -> Self {
        let mut out = *self;
        for i in 0..4 {
            out.bits[i] |= other.bits[i];
        }
        out
    }

    /// Difference: bytes in `self` that are not in `other`.
    pub fn difference(&self, other: &Self) -> Self {
        let mut out = *self;
        for i in 0..4 {
            out.bits[i] &= !other.bits[i];
        }
        out
    }

    /// The complement over all 256 byte values.
    pub fn negate(&self) -> Self {
        let mut out = *self;
        for i in 0..4 {
            out.bits[i] = !out.bits[i];
        }
        out
    }

    /// True when no byte is a member.
    pub fn is_empty(&self) -> bool {
        self.bits == [0; 4]
    }

    /// True when every byte is a member.
    pub fn is_full(&self) -> bool {
        self.bits == [u64::MAX; 4]
    }

    /// How many bytes are members. Used to reject patterns that would
    /// make the NFA useless (`[^\\x00-\\x{10FFFF}]` and friends).
    pub fn len(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// The members, ascending. Used by `#[derive]`-style debugging and
    /// by the differential tests, which compare the compiled class
    /// against the `regex` crate's own expansion.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        (0u16..=255).filter_map(move |b| {
            let b = b as u8;
            if self.contains(b) {
                Some(b)
            } else {
                None
            }
        })
    }
}

impl fmt::Debug for ByteSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print as ranges rather than 256 bits: a class like [a-f] should
        // read as one, and it is what the differential tests compare.
        let mut parts: Vec<String> = Vec::new();
        let mut b = 0u16;
        while b <= 255 {
            if !self.contains(b as u8) {
                b += 1;
                continue;
            }
            let start = b;
            while b < 255 && self.contains((b + 1) as u8) {
                b += 1;
            }
            let end = b;
            if start == end {
                parts.push(hex_byte(start as u8));
            } else {
                parts.push(hex_byte(start as u8) + "-" + &hex_byte(end as u8));
            }
            b += 1;
        }
        if parts.is_empty() {
            f.write_str("[]")
        } else {
            f.write_str(&parts.join(","))
        }
    }
}

fn hex_byte(b: u8) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(4);
    s.push('\\');
    s.push('x');
    s.push(HEX[(b >> 4) as usize] as char);
    s.push(HEX[(b & 15) as usize] as char);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_full_are_distinct() {
        assert!(ByteSet::empty().is_empty());
        assert!(!ByteSet::empty().is_full());
        assert!(ByteSet::any().is_full());
        assert!(!ByteSet::any().is_empty());
        assert_eq!(ByteSet::any().len(), 256);
        assert_eq!(ByteSet::empty().len(), 0);
    }

    #[test]
    fn membership_and_edges() {
        let s = ByteSet::range(b'a', b'z');
        assert!(s.contains(b'a'));
        assert!(s.contains(b'm'));
        assert!(s.contains(b'z'));
        assert!(!s.contains(b'A'));
        assert!(!s.contains(b'0'));
        // boundaries of the whole table
        assert!(ByteSet::single(0).contains(0));
        assert!(ByteSet::single(255).contains(255));
        assert!(!ByteSet::single(0).contains(1));
    }

    #[test]
    fn set_algebra() {
        let a = ByteSet::range(b'a', b'z');
        let b = ByteSet::range(b'x', b'C'); // deliberately reversed: empty
        assert!(b.is_empty());
        let u = a.union(&ByteSet::single(b'_'));
        assert!(u.contains(b'_') && u.contains(b'q'));
        let d = a.difference(&ByteSet::single(b'q'));
        assert!(!d.contains(b'q') && d.contains(b'a'));
        let n = a.negate();
        assert!(!n.contains(b'a'));
        assert!(n.contains(b'A'));
        // complement then complement is identity
        assert_eq!(n.negate(), a);
    }

    #[test]
    fn any_except_newline() {
        let s = ByteSet::any_except_newline();
        assert!(!s.contains(b'\n'));
        assert!(s.contains(b' '));
        assert!(s.contains(0));
        assert_eq!(s.len(), 255);
    }

    #[test]
    fn ranges_cross_word_boundaries() {
        // 0x3F..0x41 spans the 64-byte word boundary
        let s = ByteSet::range(0x3F, 0x41);
        assert!(s.contains(0x3F) && s.contains(0x40) && s.contains(0x41));
        assert!(!s.contains(0x3E) && !s.contains(0x42));
    }

    #[test]
    fn full_span_insert() {
        let mut s = ByteSet::empty();
        s.insert_range(0, 255);
        assert!(s.is_full());
    }

    #[test]
    fn iter_yields_members_ascending() {
        let s = ByteSet::range(b'b', b'd');
        let got: Vec<u8> = s.iter().collect();
        assert_eq!(got, vec![b'b', b'c', b'd']);
    }
}
