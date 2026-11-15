// SPDX-License-Identifier: Apache-2.0

//! The dispatch behind [`crate::memchr`].
//!
//! Everything in here asks the same question the rest of the crate asks --
//! *may this CPU run the AVX2 instructions?* -- and the answer comes from
//! [`crate::detect`], which is a CPUID/XGETBV probe written out by hand and
//! cached. There is no `feature = "std"` anywhere in this file, so the build
//! with `std` and the build without it reach the same kernel and produce
//! comparable numbers.
//!
//! Where this crate has no kernel of its own to offer, the upstream crate's
//! search is used unchanged: on a CPU without AVX2 the upstream crate picks
//! SSE2, and on aarch64 it picks NEON, both at compile time and both without
//! a probe.

use core::fmt;
use core::iter::Rev;

/// Search for the first occurrence of `needle` in `haystack`.
#[inline]
pub fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::one_find(needle, haystack) };
        }
    }
    ::memchr::memchr(needle, haystack)
}

/// Search for the last occurrence of `needle` in `haystack`.
#[inline]
pub fn memrchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::one_rfind(needle, haystack) };
        }
    }
    ::memchr::memrchr(needle, haystack)
}

/// Search for the first occurrence of either `needle1` or `needle2`.
#[inline]
pub fn memchr2(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::two_find(needle1, needle2, haystack) };
        }
    }
    ::memchr::memchr2(needle1, needle2, haystack)
}

/// Search for the last occurrence of either `needle1` or `needle2`.
#[inline]
pub fn memrchr2(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::two_rfind(needle1, needle2, haystack) };
        }
    }
    ::memchr::memrchr2(needle1, needle2, haystack)
}

/// Search for the first occurrence of any of the three needles.
#[inline]
pub fn memchr3(needle1: u8, needle2: u8, needle3: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::three_find(needle1, needle2, needle3, haystack) };
        }
    }
    ::memchr::memchr3(needle1, needle2, needle3, haystack)
}

/// Search for the last occurrence of any of the three needles.
#[inline]
pub fn memrchr3(needle1: u8, needle2: u8, needle3: u8, haystack: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::three_rfind(needle1, needle2, needle3, haystack) };
        }
    }
    ::memchr::memrchr3(needle1, needle2, needle3, haystack)
}

/// Count the occurrences of `needle` in `haystack`.
///
/// This is the counting counterpart of [`memchr`], and it is what the
/// iterator's `count` uses: a scan that pops the bits out of the vector
/// masks counts the whole haystack in one pass, where an iterator that
/// restarts the scan at every hit pays a call per hit.
#[inline]
fn count_one(needle: u8, haystack: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::detect::avx2() {
            // SAFETY: the probe read the CPU's own feature bits and the
            // operating system's register state, and it said the AVX2
            // instructions may run here.
            return unsafe { x86_64::one_count(needle, haystack) };
        }
    }
    ::memchr::memchr_iter(needle, haystack).count()
}

/// Returns an iterator over all occurrences of the needle in a haystack.
#[inline]
pub fn memchr_iter<'h>(needle: u8, haystack: &'h [u8]) -> Memchr<'h> {
    Memchr::new(needle, haystack)
}

/// Returns an iterator over all occurrences of the needle in a haystack, in
/// reverse.
#[inline]
pub fn memrchr_iter<'h>(needle: u8, haystack: &'h [u8]) -> Rev<Memchr<'h>> {
    Memchr::new(needle, haystack).rev()
}

/// Returns an iterator over all occurrences of the needles in a haystack.
#[inline]
pub fn memchr2_iter<'h>(needle1: u8, needle2: u8, haystack: &'h [u8]) -> Memchr2<'h> {
    Memchr2::new(needle1, needle2, haystack)
}

/// Returns an iterator over all occurrences of the needles in a haystack, in
/// reverse.
#[inline]
pub fn memrchr2_iter<'h>(needle1: u8, needle2: u8, haystack: &'h [u8]) -> Rev<Memchr2<'h>> {
    Memchr2::new(needle1, needle2, haystack).rev()
}

/// Returns an iterator over all occurrences of the needles in a haystack.
#[inline]
pub fn memchr3_iter<'h>(needle1: u8, needle2: u8, needle3: u8, haystack: &'h [u8]) -> Memchr3<'h> {
    Memchr3::new(needle1, needle2, needle3, haystack)
}

/// Returns an iterator over all occurrences of the needles in a haystack, in
/// reverse.
#[inline]
pub fn memrchr3_iter<'h>(
    needle1: u8,
    needle2: u8,
    needle3: u8,
    haystack: &'h [u8],
) -> Rev<Memchr3<'h>> {
    Memchr3::new(needle1, needle2, needle3, haystack).rev()
}

/// The AVX2 kernels of the upstream `memchr` crate, reached through its own
/// public architecture module.
///
/// The upstream crate publishes these behind an `unsafe` constructor whose
/// contract is exactly the question [`crate::detect`] answers. The
/// `#[target_feature]` on each function is what lets the upstream searcher
/// inline into it: without it, the AVX2 code would be a separate call per
/// search, and the whole point of the exercise is that it is not.
#[cfg(target_arch = "x86_64")]
mod x86_64 {
    // The leading `::` names the upstream crate, not this crate's own
    // `memchr` module -- the two are both called `memchr`, and a `use`
    // path that starts with the bare name would be ambiguous.
    use ::memchr::arch::x86_64::avx2::memchr::{One, Three, Two};

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn one_find(needle: u8, haystack: &[u8]) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        One::new_unchecked(needle).find(haystack)
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn one_rfind(needle: u8, haystack: &[u8]) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        One::new_unchecked(needle).rfind(haystack)
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn one_count(needle: u8, haystack: &[u8]) -> usize {
        let one = One::new_unchecked(needle);
        let start = haystack.as_ptr();
        // SAFETY: both pointers are derived from the haystack slice, and
        // their distance is the slice's length, which cannot overflow an
        // `isize` because a slice's length cannot.
        one.count_raw(start, start.wrapping_add(haystack.len()))
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn two_find(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        Two::new_unchecked(needle1, needle2).find(haystack)
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn two_rfind(needle1: u8, needle2: u8, haystack: &[u8]) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        Two::new_unchecked(needle1, needle2).rfind(haystack)
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn three_find(
        needle1: u8,
        needle2: u8,
        needle3: u8,
        haystack: &[u8],
    ) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        Three::new_unchecked(needle1, needle2, needle3).find(haystack)
    }

    /// # Safety
    ///
    /// The caller must have established that this CPU can run the AVX2
    /// instructions.
    #[target_feature(enable = "sse2", enable = "avx2")]
    pub(super) unsafe fn three_rfind(
        needle1: u8,
        needle2: u8,
        needle3: u8,
        haystack: &[u8],
    ) -> Option<usize> {
        // SAFETY: the caller established AVX2, which is the whole of the
        // unchecked constructor's contract; the searcher does not outlive
        // this call.
        Three::new_unchecked(needle1, needle2, needle3).rfind(haystack)
    }
}

/// The three iterators, which differ only in how many needles they carry.
///
/// The upstream crate's iterators are a restart loop over the search
/// function, and this is the same shape: each `next` re-enters the search
/// at the byte after the last hit. The one special case is the single-byte
/// iterator's `count`, which the upstream crate also specialises -- a scan
/// that pops the bits out of the vector masks counts the whole haystack in
/// one pass, where an iterator that restarts the scan at every hit pays a
/// call per hit.
macro_rules! byte_iterator {
    (
        $(#[$doc:meta])*
        $name:ident,
        needles: [$($needle:ident),+],
        find: $find:path,
        rfind: $rfind:path,
        count: $count:path $(,)?
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name<'h> {
            $($needle: u8,)+
            haystack: &'h [u8],
            /// The offset of the first byte still to be searched.
            front: usize,
            /// The offset just past the last byte still to be searched.
            back: usize,
        }

        impl<'h> $name<'h> {
            /// Returns an iterator over all occurrences of the needle bytes
            /// in the given haystack.
            ///
            /// The iterator returned implements `DoubleEndedIterator`. This
            /// means it can also be used to find occurrences in reverse
            /// order.
            #[inline]
            pub fn new($($needle: u8),+, haystack: &'h [u8]) -> $name<'h> {
                $name {
                    $($needle,)+
                    haystack,
                    front: 0,
                    back: haystack.len(),
                }
            }
        }

        impl<'h> Iterator for $name<'h> {
            type Item = usize;

            #[inline]
            fn next(&mut self) -> Option<usize> {
                if self.front >= self.back {
                    return None;
                }
                let at = $find(
                    $(self.$needle),+,
                    &self.haystack[self.front..self.back],
                )?;
                self.front += at + 1;
                Some(self.front - 1)
            }

            #[inline]
            fn count(self) -> usize {
                $count(
                    $(self.$needle),+,
                    &self.haystack[self.front..self.back],
                )
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, Some(self.back - self.front))
            }
        }

        impl<'h> DoubleEndedIterator for $name<'h> {
            #[inline]
            fn next_back(&mut self) -> Option<usize> {
                if self.front >= self.back {
                    return None;
                }
                let at = $rfind(
                    $(self.$needle),+,
                    &self.haystack[self.front..self.back],
                )?;
                self.back = self.front + at;
                Some(self.back)
            }
        }

        impl<'h> core::iter::FusedIterator for $name<'h> {}

        impl<'h> fmt::Debug for $name<'h> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("needles", &[$(&self.$needle),+])
                    .field("at", &self.front)
                    .finish()
            }
        }
    };
}

/// The counting counterpart of the two- and three-byte searches.
///
/// The upstream crate has no `count_raw` for them either, so the count is
/// the iterator's own: one search per hit.
fn count_many(needles: &[u8], haystack: &[u8]) -> usize {
    let mut n = 0usize;
    let mut front = 0usize;
    while front < haystack.len() {
        let at = match needles.len() {
            2 => memchr2(needles[0], needles[1], &haystack[front..]),
            _ => memchr3(needles[0], needles[1], needles[2], &haystack[front..]),
        };
        match at {
            Some(at) => {
                n += 1;
                front += at + 1;
            }
            None => break,
        }
    }
    n
}

/// The count for the two-byte iterator.
fn count_two(needle1: u8, needle2: u8, haystack: &[u8]) -> usize {
    count_many(&[needle1, needle2], haystack)
}

/// The count for the three-byte iterator.
fn count_three(needle1: u8, needle2: u8, needle3: u8, haystack: &[u8]) -> usize {
    count_many(&[needle1, needle2, needle3], haystack)
}

byte_iterator! {
    /// An iterator over all occurrences of a single byte in a haystack.
    ///
    /// This iterator implements `DoubleEndedIterator`, which means it can also
    /// be used to find occurrences in reverse order.
    Memchr,
    needles: [needle],
    find: memchr,
    rfind: memrchr,
    count: count_one,
}

byte_iterator! {
    /// An iterator over all occurrences of two possible bytes in a haystack.
    ///
    /// This iterator implements `DoubleEndedIterator`, which means it can also
    /// be used to find occurrences in reverse order.
    Memchr2,
    needles: [needle1, needle2],
    find: memchr2,
    rfind: memrchr2,
    count: count_two,
}

byte_iterator! {
    /// An iterator over all occurrences of three possible bytes in a
    /// haystack.
    ///
    /// This iterator implements `DoubleEndedIterator`, which means it can also
    /// be used to find occurrences in reverse order.
    Memchr3,
    needles: [needle1, needle2, needle3],
    find: memchr3,
    rfind: memrchr3,
    count: count_three,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    /// The dispatch and the upstream crate must agree, byte for byte.
    ///
    /// The upstream crate's own dispatch is the answer this crate is
    /// measured against: the two are asked the same question about the same
    /// bytes, and a build that takes the AVX2 path where the other does not
    /// is a build whose answers are not comparable. The check is a
    /// differential against the upstream functions over a corpus that
    /// includes the empty haystack, the single byte, the vector boundary and
    /// a haystack long enough to exercise the wide kernels.
    #[test]
    fn the_dispatch_agrees_with_the_upstream_crate() {
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"aa",
            b"aaaaaaaaaaaaaaaa",
            b"abcdefghijklmnopqrstuvwxyz",
            &[b'x'; 31],
            &[b'x'; 32],
            &[b'x'; 33],
            &[b'x'; 64],
            &[b'x'; 65],
        ];
        for hay in haystacks {
            for &needle in &[b'a', b'x', b'z', 0] {
                assert_eq!(
                    super::memchr(needle, hay),
                    ::memchr::memchr(needle, hay),
                    "memchr({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memrchr(needle, hay),
                    ::memchr::memrchr(needle, hay),
                    "memrchr({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memchr_iter(needle, hay).collect::<Vec<_>>(),
                    ::memchr::memchr_iter(needle, hay).collect::<Vec<_>>(),
                    "memchr_iter({needle:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memchr_iter(needle, hay).count(),
                    ::memchr::memchr_iter(needle, hay).count(),
                    "memchr_iter({needle:?}).count() over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memrchr_iter(needle, hay).collect::<Vec<_>>(),
                    ::memchr::memrchr_iter(needle, hay).collect::<Vec<_>>(),
                    "memrchr_iter({needle:?}) over {} bytes",
                    hay.len()
                );
            }
            for &(n1, n2) in &[(b'a', b'x'), (b'a', b'a'), (b'z', 0u8)] {
                assert_eq!(
                    super::memchr2(n1, n2, hay),
                    ::memchr::memchr2(n1, n2, hay),
                    "memchr2({n1:?}, {n2:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memrchr2(n1, n2, hay),
                    ::memchr::memrchr2(n1, n2, hay),
                    "memrchr2({n1:?}, {n2:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memchr2_iter(n1, n2, hay).collect::<Vec<_>>(),
                    ::memchr::memchr2_iter(n1, n2, hay).collect::<Vec<_>>(),
                    "memchr2_iter({n1:?}, {n2:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memrchr2_iter(n1, n2, hay).collect::<Vec<_>>(),
                    ::memchr::memrchr2_iter(n1, n2, hay).collect::<Vec<_>>(),
                    "memrchr2_iter({n1:?}, {n2:?}) over {} bytes",
                    hay.len()
                );
            }
            for &(n1, n2, n3) in &[(b'a', b'x', b'z'), (b'a', b'a', b'a')] {
                assert_eq!(
                    super::memchr3(n1, n2, n3, hay),
                    ::memchr::memchr3(n1, n2, n3, hay),
                    "memchr3({n1:?}, {n2:?}, {n3:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memrchr3(n1, n2, n3, hay),
                    ::memchr::memrchr3(n1, n2, n3, hay),
                    "memrchr3({n1:?}, {n2:?}, {n3:?}) over {} bytes",
                    hay.len()
                );
                assert_eq!(
                    super::memchr3_iter(n1, n2, n3, hay).collect::<Vec<_>>(),
                    ::memchr::memchr3_iter(n1, n2, n3, hay).collect::<Vec<_>>(),
                    "memchr3_iter({n1:?}, {n2:?}, {n3:?}) over {} bytes",
                    hay.len()
                );
            }
        }
    }

    /// The iterator must yield the same offsets whether it is walked from
    /// the front, from the back, or both.
    ///
    /// The forward and the backward walks share one pair of cursors, so a
    /// walk from both ends has to leave the middle alone -- and the set of
    /// offsets it yields has to be the same set the forward walk yields.
    #[test]
    fn the_iterator_walks_the_same_offsets_from_both_ends() {
        let hay = b"the quick brown fox jumps over the lazy dog";
        let forward: Vec<usize> = super::memchr_iter(b'o', hay).collect();
        let backward: Vec<usize> = super::memrchr_iter(b'o', hay).collect();
        let mut both = super::memchr_iter(b'o', hay);
        let mut mixed = Vec::new();
        while let Some(at) = both.next() {
            mixed.push(at);
            if let Some(at) = both.next_back() {
                mixed.push(at);
            }
        }
        mixed.sort_unstable();
        assert_eq!(forward, mixed);
        let mut backward_sorted = backward.clone();
        backward_sorted.sort_unstable();
        assert_eq!(forward, backward_sorted);
    }
}
