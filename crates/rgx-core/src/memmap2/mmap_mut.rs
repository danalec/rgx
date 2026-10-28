// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs read-write MmapMut handle.

use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::slice;

use crate::memmap2::mmap::Mmap;
use crate::memmap2::platform::MmapInner;

#[cfg(unix)]
use crate::memmap2::advice::Advice;
#[cfg(unix)]
use crate::memmap2::advice::UncheckedAdvice;

pub struct MmapMut {
    inner: MmapInner,
}

unsafe impl Send for MmapMut {}
unsafe impl Sync for MmapMut {}

impl MmapMut {
    pub(crate) fn from_inner(inner: MmapInner) -> MmapMut {
        MmapMut { inner }
    }

    pub unsafe fn map_mut<T: crate::memmap2::platform::MmapAsRawDesc>(
        file: T,
    ) -> io::Result<MmapMut> {
        crate::memmap2::MmapOptions::new().map_mut(file)
    }

    pub fn map_anon(length: usize) -> io::Result<MmapMut> {
        crate::memmap2::MmapOptions::new().len(length).map_anon()
    }

    pub fn flush(&self) -> io::Result<()> {
        let len = self.len();
        self.inner.flush(0, len)
    }

    pub fn flush_async(&self) -> io::Result<()> {
        let len = self.len();
        self.inner.flush_async(0, len)
    }

    pub fn flush_range(&self, offset: usize, len: usize) -> io::Result<()> {
        self.inner.flush(offset, len)
    }

    pub fn flush_async_range(&self, offset: usize, len: usize) -> io::Result<()> {
        self.inner.flush_async(offset, len)
    }

    pub fn make_read_only(self) -> io::Result<Mmap> {
        let mut inner = self.inner;
        inner.make_read_only()?;
        Ok(Mmap::from_inner(inner))
    }

    pub fn make_exec(self) -> io::Result<Mmap> {
        let mut inner = self.inner;
        inner.make_exec()?;
        Ok(Mmap::from_inner(inner))
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
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.mut_ptr()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Deref for MmapMut {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.inner.ptr(), self.inner.len()) }
    }
}

impl DerefMut for MmapMut {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.inner.mut_ptr(), self.inner.len()) }
    }
}

impl AsRef<[u8]> for MmapMut {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl AsMut<[u8]> for MmapMut {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.deref_mut()
    }
}

impl fmt::Debug for MmapMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmapMut")
            .field("ptr", &self.as_ptr())
            .field("len", &self.len())
            .finish()
    }
}
