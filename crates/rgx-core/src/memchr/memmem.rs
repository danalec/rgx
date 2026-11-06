// SPDX-License-Identifier: Apache-2.0

//! The substring search.
//!
//! ## Why this module exists
//!
//! The upstream `memchr` crate's substring search is the one thing in it
//! that cannot be reached without `std`. Its packed-pair kernel -- the one
//! that finds a needle by looking for two of its bytes at once -- is
//! published behind an `Option`-returning constructor that asks
//! `std::is_x86_feature_detected!` whether it may run, and the crate
//! answers "no" to every `no_std` build. The fallback is the SSE2 kernel,
//! which is half the width.
//!
//! The upstream crate does not publish the packed-pair kernel's unchecked
//! constructor -- `with_pair_impl` is private -- so there is no way to ask
//! it to run the wide kernel from a build without `std`. What this crate
//! has instead is its own pair scanner: [`crate::scan::pair_find`] and
//! [`crate::scan::pair_rfind`], which test the needle's two *rarest* bytes
//! at once in 32-byte blocks (64 with AVX-512) and confirm every candidate.
//! That is the same technique the upstream kernel uses, on the same pair of
//! bytes -- [`crate::frequency::rarest_pair`] is a port of the upstream
//! selection, tie-break included -- and it is behind no `std` gate at all.
//!
//! ## What this buys
//!
//! The two configurations now take the *same* path. The decision is the
//! runtime probe in [`crate::detect`], not a compile-time feature, so a
//! build with `std` and a build without it reach the same kernel and
//! produce comparable numbers.
//!
//! ## Where the upstream crate's search still runs
//!
//! On a CPU without AVX2, and on every architecture where the upstream
//! crate's vector width is decided at compile time -- aarch64's NEON, for
//! instance -- the upstream search is used unchanged. There is nothing to
//! fix there: those paths never needed `std` to be chosen, so they are the
//! same in both builds already.
//!
//! ## What is different from the upstream crate
//!
//! The *answers* are the same: the same offsets, the same "no match", the
//! same empty-needle convention. The *shape* of the API is the upstream
//! crate's, so the call sites did not move -- `find`, `rfind`, `find_iter`,
//! `rfind_iter`, `Finder`, `FinderRev`, `FinderBuilder` and `Matcher` all
//! keep their names and their meanings.
//!
//! One difference is worth naming: the upstream crate's `find_iter` yields
//! the *non-overlapping* matches, and so does this one. A caller that wants
//! the overlapping ones has to step one byte on, which is what
//! `crate::regex`'s `sub_offsets` does.

use core::fmt;

/// Returns the index of the first occurrence of `needle` in `haystack`.
///
/// If `needle` is empty, this returns `Some(0)`.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem;
///
/// assert_eq!(memmem::find(b"abcde", b"cd"), Some(2));
/// assert_eq!(memmem::find(b"abcde", b"xx"), None);
/// ```
#[must_use]
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() == 1 {
        return crate::memchr::memchr(needle[0], haystack);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            return crate::scan::pair_find(needle, haystack);
        }
    }
    ::memchr::memmem::find(haystack, needle)
}

/// Returns the index of the last occurrence to `needle` in `haystack`.
///
/// If `needle` is empty, this returns `Some(haystack.len())`.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem;
///
/// assert_eq!(memmem::rfind(b"abcde", b"cd"), Some(2));
/// assert_eq!(memmem::rfind(b"abcde", b"xx"), None);
/// ```
#[must_use]
pub fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(haystack.len());
    }
    if needle.len() == 1 {
        return crate::memchr::memrchr(needle[0], haystack);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            return crate::scan::pair_rfind(needle, haystack);
        }
    }
    ::memchr::memmem::rfind(haystack, needle)
}

/// Returns an iterator over all non-overlapping occurrences of a substring
/// in a haystack.
///
/// The iterator yields the *start* of each match. The matches do not
/// overlap: the search resumes one needle's length after each hit, so
/// `xx` in `xxx` is one match and not two.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem;
///
/// let mut matches = memmem::find_iter(b"abcabcabc", b"abc");
/// assert_eq!(matches.next(), Some(0));
/// assert_eq!(matches.next(), Some(3));
/// assert_eq!(matches.next(), Some(6));
/// assert_eq!(matches.next(), None);
/// ```
pub fn find_iter<'h, 'n, N: ?Sized + AsRef<[u8]>>(
    haystack: &'h [u8],
    needle: &'n N,
) -> FindIter<'h, 'n> {
    FindIter {
        haystack,
        needle: needle.as_ref(),
        pos: 0,
    }
}

/// Returns an iterator over all non-overlapping occurrences of a substring
/// in a haystack, in reverse order.
///
/// The iterator yields the *start* of each match, and the matches are
/// yielded from the last one to the first.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem;
///
/// let mut matches = memmem::rfind_iter(b"abcabcabc", b"abc");
/// assert_eq!(matches.next(), Some(6));
/// assert_eq!(matches.next(), Some(3));
/// assert_eq!(matches.next(), Some(0));
/// assert_eq!(matches.next(), None);
/// ```
pub fn rfind_iter<'h, 'n, N: ?Sized + AsRef<[u8]>>(
    haystack: &'h [u8],
    needle: &'n N,
) -> FindRevIter<'h, 'n> {
    FindRevIter {
        haystack,
        needle: needle.as_ref(),
        pos: Some(haystack.len()),
    }
}

/// A searcher for a substring, built once and used on many haystacks.
///
/// The needle is held by reference, and a `Finder` costs one pointer and
/// one length: there is nothing to precompute, because the two rarest bytes
/// of the needle are chosen per search from a table of byte frequencies.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem::Finder;
///
/// let finder = Finder::new(b"needle");
/// assert_eq!(finder.find(b"a needle here"), Some(2));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finder<'n> {
    needle: &'n [u8],
}

impl<'n> Finder<'n> {
    /// Creates a new finder for the given needle.
    #[must_use]
    pub fn new<B: ?Sized + AsRef<[u8]>>(needle: &'n B) -> Finder<'n> {
        Finder {
            needle: needle.as_ref(),
        }
    }

    /// Returns the index of the first occurrence of the needle in the
    /// given haystack.
    #[must_use]
    pub fn find(&self, haystack: &[u8]) -> Option<usize> {
        find(haystack, self.needle)
    }

    /// Returns the index of the last occurrence for the needle in the given
    /// haystack.
    #[must_use]
    pub fn rfind(&self, haystack: &[u8]) -> Option<usize> {
        rfind(haystack, self.needle)
    }

    /// Returns an iterator over all non-overlapping occurrences of the
    /// needle in the given haystack.
    #[must_use]
    pub fn find_iter<'h>(&self, haystack: &'h [u8]) -> FindIter<'h, 'n> {
        FindIter {
            haystack,
            needle: self.needle,
            pos: 0,
        }
    }

    /// Returns an iterator over all non-overlapping occurrences of the
    /// needle in the given haystack, in reverse order.
    #[must_use]
    pub fn rfind_iter<'h>(&self, haystack: &'h [u8]) -> FindRevIter<'h, 'n> {
        FindRevIter {
            haystack,
            needle: self.needle,
            pos: Some(haystack.len()),
        }
    }

    /// The needle this finder searches for.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.needle
    }
}

/// A searcher for the *last* occurrence of a substring, built once and used
/// on many haystacks.
///
/// # Example
///
/// ```
/// use rgx_core::memchr::memmem::FinderRev;
///
/// let finder = FinderRev::new(b"needle");
/// assert_eq!(finder.rfind(b"a needle and a needle"), Some(15));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinderRev<'n> {
    needle: &'n [u8],
}

impl<'n> FinderRev<'n> {
    /// Creates a new finder for the given needle.
    #[must_use]
    pub fn new<B: ?Sized + AsRef<[u8]>>(needle: &'n B) -> FinderRev<'n> {
        FinderRev {
            needle: needle.as_ref(),
        }
    }

    /// Returns the index of the last occurrence for the needle in the given
    /// haystack.
    #[must_use]
    pub fn rfind(&self, haystack: &[u8]) -> Option<usize> {
        rfind(haystack, self.needle)
    }

    /// Returns an iterator over all non-overlapping occurrences of the
    /// needle in the given haystack, in reverse order.
    #[must_use]
    pub fn rfind_iter<'h>(&self, haystack: &'h [u8]) -> FindRevIter<'h, 'n> {
        FindRevIter {
            haystack,
            needle: self.needle,
            pos: Some(haystack.len()),
        }
    }

    /// The needle this finder searches for.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.needle
    }
}

/// A builder for a [`Finder`] and a [`FinderRev`].
///
/// It exists so that the upstream crate's API is here whole; there is
/// nothing to configure, and the builder carries no state.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FinderBuilder {
    _private: (),
}

impl FinderBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> FinderBuilder {
        FinderBuilder { _private: () }
    }

    /// Build a [`Finder`] for the given needle.
    #[must_use]
    pub fn build<'n, B: ?Sized + AsRef<[u8]>>(&self, needle: &'n B) -> Finder<'n> {
        Finder::new(needle)
    }

    /// Build a [`FinderRev`] for the given needle.
    #[must_use]
    pub fn build_rev<'n, B: ?Sized + AsRef<[u8]>>(&self, needle: &'n B) -> FinderRev<'n> {
        FinderRev::new(needle)
    }

    /// Build a [`Matcher`] for the given haystack and needle.
    #[must_use]
    pub fn matcher<'h, 'n, B: ?Sized + AsRef<[u8]>>(
        &self,
        haystack: &'h [u8],
        needle: &'n B,
    ) -> Matcher<'h, 'n> {
        Matcher {
            haystack,
            finder: Finder::new(needle),
        }
    }
}

/// A matcher for a substring in a particular haystack.
///
/// It is the haystack and the needle together, and it is what the upstream
/// crate's `FinderBuilder::matcher` builds.
#[derive(Clone, Debug)]
pub struct Matcher<'h, 'n> {
    haystack: &'h [u8],
    finder: Finder<'n>,
}

impl<'h, 'n> Matcher<'h, 'n> {
    /// Returns the index of the first occurrence for the needle in the
    /// haystack.
    #[must_use]
    pub fn find(&self) -> Option<usize> {
        self.finder.find(self.haystack)
    }

    /// Returns the index of the last occurrence for the needle in the
    /// haystack.
    #[must_use]
    pub fn rfind(&self) -> Option<usize> {
        self.finder.rfind(self.haystack)
    }

    /// Returns an iterator over all non-overlapping occurrences of the
    /// needle in the haystack.
    #[must_use]
    pub fn find_iter(&self) -> FindIter<'h, 'n> {
        self.finder.find_iter(self.haystack)
    }

    /// Returns an iterator over all non-overlapping occurrences of the
    /// needle in the haystack, in reverse order.
    #[must_use]
    pub fn rfind_iter(&self) -> FindRevIter<'h, 'n> {
        self.finder.rfind_iter(self.haystack)
    }
}

/// An iterator over the non-overlapping occurrences of a substring in a
/// haystack.
///
/// The iterator yields the *start* of each match. The matches do not
/// overlap: the search resumes one needle's length after each hit, so `xx`
/// in `xxx` is one match and not two.
#[derive(Clone, Debug)]
pub struct FindIter<'h, 'n> {
    haystack: &'h [u8],
    needle: &'n [u8],
    /// The offset the next search starts from.
    pos: usize,
}

impl<'h, 'n> Iterator for FindIter<'h, 'n> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let haystack = self.haystack.get(self.pos..)?;
        let idx = find(haystack, self.needle)?;
        let pos = self.pos + idx;
        // The empty needle matches at every offset, so the search has to
        // step on even when the needle is empty -- otherwise it would
        // report the same offset forever.
        self.pos = pos + self.needle.len().max(1);
        Some(pos)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self.haystack.len().checked_sub(self.pos) {
            None => (0, Some(0)),
            Some(haystack_len) => match self.needle.len() {
                // An empty needle matches at every offset, including the
                // one just past the end.
                0 => (haystack_len.saturating_add(1), haystack_len.checked_add(1)),
                needle_len => (0, Some(haystack_len / needle_len)),
            },
        }
    }
}

/// An iterator over the non-overlapping occurrences of a substring in a
/// haystack, in reverse order.
///
/// The iterator yields the *start* of each match, and the matches are
/// yielded from the last one to the first.
#[derive(Clone, Debug)]
pub struct FindRevIter<'h, 'n> {
    haystack: &'h [u8],
    needle: &'n [u8],
    /// The offset the next search ends at, exclusive.
    pos: Option<usize>,
}

impl<'h, 'n> Iterator for FindRevIter<'h, 'n> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let pos = self.pos?;
        let result = rfind(&self.haystack[..pos], self.needle)?;
        // The next match has to end before this one starts, so the search
        // is bounded by the match that was just reported.
        //
        // The empty needle is the case where the bound does not move: it
        // matches at the end of the haystack, so the next search would
        // find the same offset again and the iterator would never end.
        // The bound steps on by one instead, and the iterator yields the
        // empty needle's matches from the end down to zero.
        if pos == result {
            self.pos = pos.checked_sub(1);
        } else {
            self.pos = Some(result);
        }
        Some(result)
    }
}

/// The `Debug` of a builder must not print its private field: it carries
/// no state, and the name is the whole of what it is.
impl fmt::Debug for FinderBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FinderBuilder")
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    /// The answers must be the upstream crate's answers.
    ///
    /// The upstream crate's substring search is the oracle: it is the
    /// implementation this module replaces, and a difference in the offsets
    /// it reports is a difference in what rgx finds. The corpus is the
    /// shapes that break a scanner -- the empty haystack, a haystack
    /// shorter than the needle, a needle at the very end, a needle that
    /// repeats itself, a needle whose two rarest bytes are at neither end,
    /// and a needle long enough to leave the first block.
    #[test]
    fn the_answers_are_the_upstream_crates_answers() {
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abcabcabc",
            b"aaaaaaaaaaaaaaaa",
            b"the quick brown fox jumps over the lazy dog",
            b"needle12345",
            b"needle12345 needle12345 needle12345",
            &[b'x'; 64],
            &[b'x'; 65],
            &[b'x'; 128],
        ];
        let needles: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"xx",
            b"needle",
            b"needle12345",
            b"zz",
            b"quick",
            b"e",
        ];
        for hay in haystacks {
            for needle in needles {
                assert_eq!(
                    super::find(hay, needle),
                    ::memchr::memmem::find(hay, needle),
                    "find({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::rfind(hay, needle),
                    ::memchr::memmem::rfind(hay, needle),
                    "rfind({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::find_iter(hay, needle).collect::<Vec<_>>(),
                    ::memchr::memmem::find_iter(hay, needle).collect::<Vec<_>>(),
                    "find_iter({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::rfind_iter(hay, needle).collect::<Vec<_>>(),
                    ::memchr::memmem::rfind_iter(hay, needle).collect::<Vec<_>>(),
                    "rfind_iter({needle:?}) over {} bytes",
                    hay.len()
                );
            }
        }
    }

    /// The pair scanner and the upstream crate must agree on a haystack
    /// long enough to leave the first block.
    ///
    /// The scanner's blocks are 32 bytes wide (64 with AVX-512) and the
    /// pair is the needle's two rarest bytes, which may sit at any two
    /// offsets inside it. A haystack of 300 bytes with a needle that
    /// occurs at many offsets exercises the block walk, the tail, and the
    /// confirmation at both ends.
    #[test]
    fn the_pair_scanner_agrees_with_the_upstream_crate() {
        let mut hay = Vec::new();
        let mut x: u64 = 0x243f_6a88_85a3_08d3;
        for _ in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            hay.push((x % 17) as u8 + b'a');
        }
        // Plant a needle at a few offsets, including one that straddles a
        // block boundary and one at the very end.
        for (needle, at) in [
            (&b"qq"[..], 31usize),
            (&b"qq"[..], 32),
            (&b"qq"[..], 63),
            (&b"qq"[..], 64),
            (&b"zzz"[..], 128),
            (&b"zzz"[..], 290),
        ] {
            let mut h = hay.clone();
            h[at..at + needle.len()].copy_from_slice(needle);
            assert_eq!(
                super::find(&h, needle),
                ::memchr::memmem::find(&h, needle),
                "find({needle:?}) planted at {at}"
            );
            assert_eq!(
                super::rfind(&h, needle),
                ::memchr::memmem::rfind(&h, needle),
                "rfind({needle:?}) planted at {at}"
            );
        }
    }
}
