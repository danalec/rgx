// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs Windows side.
//!
//! FFI signatures are inlined in `extern "system"` blocks; no windows-sys
//! dependency.

use std::io;
use std::os::windows::io::RawHandle;
use std::ptr;

use crate::memmap2::error::Error;

#[inline]
fn page_size() -> usize {
    super::page_size()
}

pub struct MmapInner {
    base: *mut u8,
    len: usize,
    handle: Option<RawHandle>,
    aligned_base: *mut u8,
}

unsafe impl Send for MmapInner {}
unsafe impl Sync for MmapInner {}

impl Drop for MmapInner {
    fn drop(&mut self) {
        if !self.aligned_base.is_null() {
            unsafe {
                UnmapViewOfFile(self.aligned_base as *mut std::ffi::c_void);
            }
        }
        if let Some(handle) = self.handle {
            unsafe {
                CloseHandle(handle);
            }
        }
    }
}

impl MmapInner {
    fn new_inner(
        len: usize,
        prot: u32,
        access_mask: u32,
        fd: RawHandle,
        offset: u64,
    ) -> io::Result<MmapInner> {
        if std::mem::size_of::<usize>() < 8 && len > isize::MAX as usize {
            return Err(crate::memmap2::error::to_io_error(Error::LengthOverflow).into());
        }
        let granularity = allocation_granularity();
        if offset % granularity != 0 {
            return Err(io::Error::from_raw_os_error(ERROR_MAPPED_ALIGNMENT));
        }
        if len == 0 {
            return Ok(MmapInner {
                base: ptr::null_mut(),
                len: 0,
                handle: None,
                aligned_base: ptr::null_mut(),
            });
        }
        // The view size must fit within the file size; use the
        // user-visible length directly.
        let view_len = len;
        let lo = (offset & 0xFFFF_FFFF) as u32;
        let hi = (offset >> 32) as u32;
        let mapping_handle =
            unsafe { CreateFileMappingW(fd, ptr::null_mut(), prot, 0, 0, ptr::null_mut()) };
        if mapping_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let view = unsafe { MapViewOfFile(mapping_handle, access_mask, hi, lo, view_len as usize) };
        unsafe {
            CloseHandle(mapping_handle);
        }
        if view.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut new_handle: RawHandle = ptr::null_mut();
        let cur_proc = get_current_process();
        let ok = unsafe {
            DuplicateHandle(
                cur_proc,
                fd,
                cur_proc,
                &mut new_handle,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            unsafe {
                UnmapViewOfFile(view);
            }
            return Err(io::Error::last_os_error());
        }
        Ok(MmapInner {
            base: view as *mut u8,
            len,
            handle: Some(new_handle),
            aligned_base: view as *mut u8,
        })
    }

    pub fn map(len: usize, fd: RawHandle, offset: u64, _populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, PAGE_READONLY, FILE_MAP_READ, fd, offset)
    }

    pub fn map_exec(
        len: usize,
        fd: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, PAGE_EXECUTE_READ, FILE_MAP_READ, fd, offset)
    }

    pub fn map_mut(
        len: usize,
        fd: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, PAGE_READWRITE, FILE_MAP_WRITE, fd, offset)
    }

    pub fn map_copy(
        len: usize,
        fd: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, PAGE_WRITECOPY, FILE_MAP_COPY, fd, offset)
    }

    pub fn map_copy_read_only(
        len: usize,
        fd: RawHandle,
        offset: u64,
        _populate: bool,
    ) -> io::Result<MmapInner> {
        MmapInner::new_inner(len, PAGE_WRITECOPY, FILE_MAP_READ, fd, offset)
    }

    pub fn map_anon(len: usize, _stack: bool, _populate: bool) -> io::Result<MmapInner> {
        if std::mem::size_of::<usize>() < 8 && len > isize::MAX as usize {
            return Err(crate::memmap2::error::to_io_error(Error::LengthOverflow).into());
        }
        if len == 0 {
            return Ok(MmapInner {
                base: ptr::null_mut(),
                len: 0,
                handle: None,
                aligned_base: ptr::null_mut(),
            });
        }
        let page = page_size();
        let view_len = len.next_multiple_of(page);
        let mapping_handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                PAGE_READWRITE,
                0,
                view_len as u32,
                ptr::null_mut(),
            )
        };
        if mapping_handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let view =
            unsafe { MapViewOfFile(mapping_handle, FILE_MAP_WRITE, 0, 0, view_len as usize) };
        unsafe {
            CloseHandle(mapping_handle);
        }
        if view.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(MmapInner {
            base: view as *mut u8,
            len,
            handle: None,
            aligned_base: view as *mut u8,
        })
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        let r = unsafe { FlushViewOfFile(self.base.add(offset) as *mut std::ffi::c_void, len) };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let r = unsafe { FlushViewOfFile(self.base.add(offset) as *mut std::ffi::c_void, len) };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        self.virtual_protect(PAGE_READONLY)
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        self.virtual_protect(PAGE_EXECUTE_READ)
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        self.virtual_protect(PAGE_READWRITE)
    }

    fn virtual_protect(&mut self, prot: u32) -> io::Result<()> {
        if self.aligned_base.is_null() {
            return Ok(());
        }
        let page = page_size();
        let view_len = self.len.max(1).next_multiple_of(page);
        let mut old_prot: u32 = 0;
        let r = unsafe {
            VirtualProtect(
                self.aligned_base as *mut std::ffi::c_void,
                view_len as usize,
                prot,
                &mut old_prot,
            )
        };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn advise(&self, _advice: i32, _offset: usize, _len: usize) -> io::Result<()> {
        Ok(())
    }

    pub fn lock(&self) -> io::Result<()> {
        if self.aligned_base.is_null() {
            return Ok(());
        }
        let page = page_size();
        let view_len = self.len.max(1).next_multiple_of(page);
        let r = unsafe {
            VirtualLock(
                self.aligned_base as *mut std::ffi::c_void,
                view_len as usize,
            )
        };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn unlock(&self) -> io::Result<()> {
        if self.aligned_base.is_null() {
            return Ok(());
        }
        let page = page_size();
        let view_len = self.len.max(1).next_multiple_of(page);
        let r = unsafe {
            VirtualUnlock(
                self.aligned_base as *mut std::ffi::c_void,
                view_len as usize,
            )
        };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.base
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.base
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
}

fn allocation_granularity() -> u64 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHE: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached as u64;
    }
    #[repr(C)]
    #[derive(Default)]
    struct SystemInfo {
        _arch: u16,
        _reserved: u16,
        page_size: u32,
        _min_addr: *mut std::ffi::c_void,
        _max_addr: *mut std::ffi::c_void,
        _active_mask: *mut u32,
        _procs: u32,
        _proc_type: u32,
        allocation_granularity: u32,
        _proc_level: u16,
        _proc_revision: u16,
    }
    extern "system" {
        fn GetSystemInfo(info: *mut SystemInfo);
    }
    let mut info = SystemInfo::default();
    unsafe {
        GetSystemInfo(&mut info);
    }
    CACHE.store(info.allocation_granularity as usize, Ordering::Relaxed);
    info.allocation_granularity as u64
}

fn get_current_process() -> RawHandle {
    extern "system" {
        fn GetCurrentProcess() -> RawHandle;
    }
    unsafe { GetCurrentProcess() }
}

const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE_READ: u32 = 0x20;
const FILE_MAP_COPY: u32 = 0x0001;
const FILE_MAP_WRITE: u32 = 0x0002;
const FILE_MAP_READ: u32 = 0x0004;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const ERROR_MAPPED_ALIGNMENT: i32 = 1132;
const INVALID_HANDLE_VALUE: RawHandle = -1i32 as RawHandle;

extern "system" {
    fn CreateFileMappingW(
        file: RawHandle,
        attrs: *mut std::ffi::c_void,
        protect: u32,
        max_size_high: u32,
        max_size_low: u32,
        name: *const u16,
    ) -> RawHandle;

    fn MapViewOfFile(
        mapping: RawHandle,
        access: u32,
        offset_high: u32,
        offset_low: u32,
        bytes_to_map: usize,
    ) -> *mut std::ffi::c_void;

    fn UnmapViewOfFile(base: *mut std::ffi::c_void) -> i32;

    fn FlushViewOfFile(base: *mut std::ffi::c_void, bytes: usize) -> i32;

    fn VirtualProtect(
        addr: *mut std::ffi::c_void,
        size: usize,
        new_prot: u32,
        old_prot: *mut u32,
    ) -> i32;

    fn VirtualLock(addr: *mut std::ffi::c_void, size: usize) -> i32;
    fn VirtualUnlock(addr: *mut std::ffi::c_void, size: usize) -> i32;

    fn CloseHandle(handle: RawHandle) -> i32;

    fn DuplicateHandle(
        src_process: RawHandle,
        src: RawHandle,
        tgt_process: RawHandle,
        out: *mut RawHandle,
        desired_access: u32,
        inherit: i32,
        options: u32,
    ) -> i32;
}
