# platform

## Overview
The operating-system half of the memory-mapping module: one `MmapInner` per supported platform, plus the small helpers they share. The file selection is a `cfg` ladder over `linux`, `macos`, `freebsd` and `windows`, with a `fallback` for every other target.

The platforms are not interchangeable behind one interface, and the differences are the reason the module is split this way. Unix platforms map with `mmap(2)` and take the file descriptor; Windows maps with `CreateFileMappingW`/`MapViewOfFile` and takes a handle, which it duplicates and owns, and its teardown (`UnmapViewOfFile`) is serial and expensive enough that the pack store leaks mappings deliberately rather than pay it on every query. The `fallback` is a stub that maps nothing and refuses the five file-mapping calls — it exists so an unsupported target compiles rather than fails with a missing-module error.

The FFI signatures are inlined in `extern "system"` blocks; there is no `windows-sys` dependency and no `libc` dependency on the Windows side.

## Interface
- `pub(crate) struct MmapInner` — the platform handle. Every platform defines one with the same shape of API:
  - `map(len, fd, offset, populate) -> io::Result<MmapInner>`, `map_exec`, `map_mut`, `map_copy`, `map_copy_read_only`, `map_anon(len, stack, populate)` — on the fallback the descriptor is a `&File`, not a raw fd.
  - `flush(offset, len)`, `flush_async(offset, len)`.
  - `make_read_only()`, `make_exec()`, `make_mut()`.
  - `advise(advice, offset, len)`.
  - `lock()`, `unlock()`.
  - `ptr() -> *const u8`, `mut_ptr() -> *mut u8`, `len() -> usize`; the fallback adds `map_file(file: &File, want: usize)`.
- `pub(crate) fn page_size() -> usize` — the OS page size; `sysconf(_SC_PAGESIZE)` on Unix, `GetSystemInfo` on Windows (cached in a `OnceLock`), and 4096 as the fallback.
- `pub(crate) fn file_len(file: &File) -> io::Result<u64>` — the size of an open file.
- `pub(crate) fn file_len_for_desc(desc: &MmapRawDescriptor) -> io::Result<u64>` — `fstat` on Unix, `GetFileSizeEx` on Windows.
- `pub trait MmapAsRawDesc` — the trait a type must implement to be mapped; implemented for `RawFd`/`RawHandle` and for `&T` where `T: AsRawFd`/`AsRawHandle`, and on the fallback target only for `&File`.
- `pub struct MmapRawDescriptor` — the platform's raw descriptor type, a newtype over the raw fd or handle; on the fallback target it carries a lifetime and wraps a `&File`.

## Invariants
- Exactly one `MmapInner` implementation is compiled per target; the `cfg` ladder in `mod.rs` selects it and the others are not part of the build.
- `MmapInner` owns its mapping: it is unmapped when it is dropped, and on Windows the view is unmapped before the handle is closed.
- `MmapInner` is `Send + Sync` on every platform (declared `unsafe impl` where the raw pointer requires it), so a mapping may cross threads.
- `page_size()` is stable for the life of the process and never returns zero; a `sysconf` that fails falls back to 4096.
- `advise` asks `super::refuse_unavailable` first: the advices that only Linux has are turned down before the syscall, because a kernel that does not know a number reads it as an instruction it does know — FreeBSD's `MADV_PROTECT` is 10 and Linux's `MADV_DONTFORK` is 10 too. The `Advice` enum keeps one shape on every platform precisely so callers need no `cfg` of their own, and the refusal is what carries that promise.
- The `fallback` implementation refuses the five file-mapping entry points; `map_anon` succeeds with a heap buffer of zeros, and `flush`, `flush_async`, `make_read_only`, `make_exec`, `make_mut`, `advise`, `lock` and `unlock` all return `Ok(())`.

## Side Effects
- This is the only part of the crate that maps memory: `mmap`/`munmap`/`msync`/`madvise`/`mlock`/`munlock` on Unix, `CreateFileMappingW`/`MapViewOfFile`/`UnmapViewOfFile`/`FlushViewOfFile`/`VirtualLock`/`VirtualUnlock` on Windows.
- `MmapInner::drop` unmaps the view and, on Windows, closes the handle it duplicated; the Unix drop only `munmap`s. There is no file lock: `lock()` takes a page lock.
- `lock()`/`unlock()` change the process's page-locking state; `make_read_only()`, `make_exec()` and `make_mut()` change the mapping's protection.
- The module reads the size of an open file through `stat`/`GetFileSizeEx`; it opens nothing itself.

## Verification
- Run: `cargo test --release --locked --workspace`
