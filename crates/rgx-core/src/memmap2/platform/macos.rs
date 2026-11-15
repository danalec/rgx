// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs macOS side.

use std::io;
use std::os::unix::io::RawFd;
use std::ptr;

use crate::memmap2::error::{to_io_error, Error};

const MAP_POPULATE: libc::c_int = 0;
const MAP_STACK: libc::c_int = 0;

pub struct MmapInner {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for MmapInner {}
unsafe impl Sync for MmapInner {}

impl Drop for MmapInner {
    fn drop(&mut self) {
        let (aligned_ptr, aligned_len) = self.unaligned_to_aligned();
        unsafe {
            libc::munmap(aligned_ptr.cast(), aligned_len);
        }
    }
}

impl MmapInner {
    fn unaligned_to_aligned(&self) -> (*mut u8, usize) {
        let page = super::page_size();
        if self.len == 0 {
            (self.ptr, 1)
        } else {
            let off = self.ptr as usize % page;
            (unsafe { self.ptr.sub(off) }, self.len + off)
        }
    }

    fn new_inner(
        len: usize,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: RawFd,
        offset: u64,
    ) -> io::Result<MmapInner> {
        if std::mem::size_of::<usize>() < 8 && len > isize::MAX as usize {
            return Err(to_io_error(Error::LengthOverflow).into());
        }
        let page = super::page_size() as u64;
        let alignment = offset % page;
        let aligned_offset = offset - alignment;
        let map_len = len
            .checked_add(alignment as usize)
            .ok_or_else(|| to_io_error(Error::LengthOverflow))?;
        let map_len = map_len.max(1);
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len as libc::size_t,
                prot,
                flags,
                fd,
                aligned_offset as libc::off_t,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = unsafe { (raw as *mut u8).add(alignment as usize) };
        Ok(MmapInner { ptr, len })
    }

    pub fn map(len: usize, fd: RawFd, offset: u64, _populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, libc::PROT_READ, libc::MAP_SHARED, fd, offset)
    }

    pub fn map_exec(len: usize, fd: RawFd, offset: u64, _populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_inner(
            len,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            offset,
        )
    }

    pub fn map_mut(len: usize, fd: RawFd, offset: u64, _populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_inner(
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            offset,
        )
    }

    pub fn map_copy(len: usize, fd: RawFd, offset: u64, _populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_inner(
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            offset,
        )
    }

    pub fn map_copy_read_only(
        len: usize,
        fd: RawFd,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, libc::PROT_READ, libc::MAP_PRIVATE, fd, offset)
    }

    pub fn map_anon(len: usize, _stack: bool, _populate: bool) -> io::Result<MmapInner> {
        if std::mem::size_of::<usize>() < 8 && len > isize::MAX as usize {
            return Err(to_io_error(Error::LengthOverflow).into());
        }
        let map_len = len.max(1);
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_len as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(MmapInner {
            ptr: raw as *mut u8,
            len,
        })
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        let r = unsafe {
            libc::msync(
                self.ptr.add(offset) as *mut libc::c_void,
                len as libc::size_t,
                libc::MS_SYNC,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let r = unsafe {
            libc::msync(
                self.ptr.add(offset) as *mut libc::c_void,
                len as libc::size_t,
                libc::MS_ASYNC,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        let (ptr, len) = self.unaligned_to_aligned();
        let r = unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len as libc::size_t,
                libc::PROT_READ,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        let (ptr, len) = self.unaligned_to_aligned();
        let r = unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len as libc::size_t,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        let (ptr, len) = self.unaligned_to_aligned();
        let r = unsafe {
            libc::mprotect(
                ptr as *mut libc::c_void,
                len as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn advise(&self, advice: libc::c_int, offset: usize, len: usize) -> io::Result<()> {
        super::refuse_unavailable(advice)?;
        let r = unsafe {
            libc::madvise(
                self.ptr.add(offset) as *mut libc::c_void,
                len as libc::size_t,
                advice,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn lock(&self) -> io::Result<()> {
        let (_ptr, len) = self.unaligned_to_aligned();
        let r = unsafe { libc::mlock(_ptr as *const libc::c_void, len as libc::size_t) };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn unlock(&self) -> io::Result<()> {
        let (_ptr, len) = self.unaligned_to_aligned();
        let r = unsafe { libc::munlock(_ptr as *const libc::c_void, len as libc::size_t) };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.ptr
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}
