// SPDX-License-Identifier: Apache-2.0

//! Independent reimplementation of memmap2-rs platform dispatch.

use std::fs::File;
use std::io;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
use std::mem;
use std::ops::{Deref, DerefMut};
use std::slice;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use self::linux::MmapInner;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(crate) use self::macos::MmapInner;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub(crate) use self::freebsd::MmapInner;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use self::windows::MmapInner;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
mod fallback;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
pub(crate) use self::fallback::MmapInner;

pub(crate) fn page_size() -> usize {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p > 0 {
            p as usize
        } else {
            4096
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::sync::OnceLock;
        static CACHE: OnceLock<usize> = OnceLock::new();
        *CACHE.get_or_init(|| unsafe {
            #[repr(C)]
            #[derive(Default)]
            struct SystemInfo {
                _arch: u16,
                _reserved: u16,
                dw_page_size: u32,
                _min_addr: *mut std::ffi::c_void,
                _max_addr: *mut std::ffi::c_void,
                _active_mask: *mut u32,
                _procs: u32,
                _proc_type: u32,
                _alloc_granularity: u32,
                _proc_level: u16,
                _proc_revision: u16,
            }
            extern "system" {
                fn GetSystemInfo(lp_system_info: *mut SystemInfo);
            }
            let mut info = SystemInfo::default();
            GetSystemInfo(&mut info);
            info.dw_page_size as usize
        })
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        4096
    }
}

pub(crate) fn file_len(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.len())
}

/// The refusal of an advice this platform does not have.
///
/// The seven advices that only Linux has are numbers Linux owns, and a
/// number a kernel does not know is not an error but an instruction it
/// does know: FreeBSD's `MADV_PROTECT` is 10 and Linux's `MADV_DONTFORK`
/// is 10 too, so handing the number over would change the protection of
/// the mapping instead of turning the advice down.
///
/// The rule is one rule for the three unix platforms: Linux has the seven
/// and refuses nothing, and the two BSDs have the five that every unix
/// kernel has and refuse the other seven.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub(crate) fn refuse_unavailable(advice: libc::c_int) -> io::Result<()> {
    if crate::memmap2::advice::is_available(advice) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this advice is a Linux one and this kernel does not have it",
    ))
}

pub(crate) fn file_len_for_desc(desc: &MmapRawDescriptor) -> io::Result<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        let mut stat: libc::stat = unsafe { mem::zeroed() };
        let r = unsafe { libc::fstat(desc.0, &mut stat) };
        if r == 0 {
            Ok(stat.st_size as u64)
        } else {
            Err(io::Error::last_os_error())
        }
    }
    #[cfg(target_os = "windows")]
    {
        let handle = desc.0;
        let mut size: i64 = 0;
        let r = unsafe { GetFileSizeEx(handle, &mut size) };
        if r == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(size as u64)
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = desc;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "file_len_for_desc is unavailable on this platform",
        ))
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetFileSizeEx(file: *mut std::ffi::c_void, file_size: *mut i64) -> i32;
}

pub(crate) fn map(
    desc: &MmapRawDescriptor,
    len: usize,
    offset: u64,
    populate: bool,
) -> io::Result<MmapInner> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        MmapInner::map(len, desc.0, offset, populate)
    }
    #[cfg(target_os = "windows")]
    {
        MmapInner::map(len, desc.0, offset, populate)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = (desc, len, offset, populate);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory mapping is not supported on this platform",
        ))
    }
}

pub(crate) fn map_exec(
    desc: &MmapRawDescriptor,
    len: usize,
    offset: u64,
    populate: bool,
) -> io::Result<MmapInner> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        MmapInner::map_exec(len, desc.0, offset, populate)
    }
    #[cfg(target_os = "windows")]
    {
        MmapInner::map_exec(len, desc.0, offset, populate)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = (desc, len, offset, populate);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory mapping is not supported on this platform",
        ))
    }
}

pub(crate) fn map_mut(
    desc: &MmapRawDescriptor,
    len: usize,
    offset: u64,
    populate: bool,
) -> io::Result<MmapInner> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        MmapInner::map_mut(len, desc.0, offset, populate)
    }
    #[cfg(target_os = "windows")]
    {
        MmapInner::map_mut(len, desc.0, offset, populate)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = (desc, len, offset, populate);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory mapping is not supported on this platform",
        ))
    }
}

pub(crate) fn map_copy(
    desc: &MmapRawDescriptor,
    len: usize,
    offset: u64,
    populate: bool,
) -> io::Result<MmapInner> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        MmapInner::map_copy(len, desc.0, offset, populate)
    }
    #[cfg(target_os = "windows")]
    {
        MmapInner::map_copy(len, desc.0, offset, populate)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = (desc, len, offset, populate);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory mapping is not supported on this platform",
        ))
    }
}

pub(crate) fn map_copy_read_only(
    desc: &MmapRawDescriptor,
    len: usize,
    offset: u64,
    populate: bool,
) -> io::Result<MmapInner> {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        MmapInner::map_copy_read_only(len, desc.0, offset, populate)
    }
    #[cfg(target_os = "windows")]
    {
        MmapInner::map_copy_read_only(len, desc.0, offset, populate)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        let _ = (desc, len, offset, populate);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "memory mapping is not supported on this platform",
        ))
    }
}

pub(crate) fn map_anon(len: usize, stack: bool, populate: bool) -> io::Result<MmapInner> {
    MmapInner::map_anon(len, stack, populate)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub struct MmapRawDescriptor(pub std::os::unix::io::RawFd);
#[cfg(target_os = "windows")]
pub struct MmapRawDescriptor(pub std::os::windows::io::RawHandle);
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
pub struct MmapRawDescriptor<'a>(pub &'a File);

pub trait MmapAsRawDesc {
    fn as_raw_desc(&self) -> MmapRawDescriptor;
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
impl MmapAsRawDesc for std::os::unix::io::RawFd {
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(*self)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
impl<'a, T> MmapAsRawDesc for &'a T
where
    T: std::os::unix::io::AsRawFd,
{
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(self.as_raw_fd())
    }
}

#[cfg(target_os = "windows")]
impl MmapAsRawDesc for std::os::windows::io::RawHandle {
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(*self)
    }
}

#[cfg(target_os = "windows")]
impl<'a, T> MmapAsRawDesc for &'a T
where
    T: std::os::windows::io::AsRawHandle,
{
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(self.as_raw_handle())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
)))]
impl<'a> MmapAsRawDesc for &'a File {
    fn as_raw_desc(&self) -> MmapRawDescriptor {
        MmapRawDescriptor(self)
    }
}

pub(crate) fn slice_from_inner(inner: &MmapInner) -> &[u8] {
    unsafe { slice::from_raw_parts(inner.ptr(), inner.len()) }
}

pub(crate) fn slice_from_inner_mut(inner: &mut MmapInner) -> &mut [u8] {
    unsafe { slice::from_raw_parts_mut(inner.mut_ptr(), inner.len()) }
}

impl Deref for MmapInner {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        slice_from_inner(self)
    }
}

impl DerefMut for MmapInner {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        slice_from_inner_mut(self)
    }
}
