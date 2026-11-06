// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs read-only Mmap handle.

use std::fmt;
use std::io;
use std::ops::Deref;
use std::slice;

use crate::memmap2::platform::MmapInner;

#[cfg(unix)]
use crate::memmap2::advice::Advice;
#[cfg(unix)]
use crate::memmap2::advice::UncheckedAdvice;

pub struct Mmap {
    inner: MmapInner,
}

unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    pub(crate) fn from_inner(inner: MmapInner) -> Mmap {
        Mmap { inner }
    }

    pub unsafe fn map<T: crate::memmap2::platform::MmapAsRawDesc>(file: T) -> io::Result<Mmap> {
        crate::memmap2::MmapOptions::new().map(file)
    }

    pub fn make_mut(self) -> io::Result<crate::memmap2::MmapMut> {
        let mut inner = self.inner;
        inner.make_mut()?;
        Ok(crate::memmap2::MmapMut::from_inner(inner))
    }

    #[cfg(unix)]
    pub fn advise(&self, advice: Advice) -> io::Result<()> {
        self.inner
            .advise(advice as libc::c_int, 0, self.inner.len())
    }

    #[cfg(unix)]
    pub unsafe fn unchecked_advise(&self, advice: UncheckedAdvice) -> io::Result<()> {
        self.inner
            .advise(advice as libc::c_int, 0, self.inner.len())
    }

    #[cfg(unix)]
    pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> io::Result<()> {
        self.inner.advise(advice as libc::c_int, offset, len)
    }

    #[cfg(unix)]
    pub unsafe fn unchecked_advise_range(
        &self,
        advice: UncheckedAdvice,
        offset: usize,
        len: usize,
    ) -> io::Result<()> {
        self.inner.advise(advice as libc::c_int, offset, len)
    }

    #[cfg(unix)]
    pub fn lock(&self) -> io::Result<()> {
        self.inner.lock()
    }

    #[cfg(unix)]
    pub fn unlock(&self) -> io::Result<()> {
        self.inner.unlock()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Deref for Mmap {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.inner.ptr(), self.inner.len()) }
    }
}

impl AsRef<[u8]> for Mmap {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl fmt::Debug for Mmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mmap")
            .field("ptr", &self.as_ptr())
            .field("len", &self.len())
            .finish()
    }
}
