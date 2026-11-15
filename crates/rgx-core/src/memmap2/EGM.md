# memmap2

## Overview
An independent reimplementation of `memmap2-rs` upstream commit f16835d (v0.9.0), written from the upstream source to understand the public API, with no verbatim copies. Upstream is `RazrFalcon/memmap2-rs`, copyright 2015 Dan Burkert and 2020 Yevhenii Reizner, used under Apache-2.0; the provenance is recorded in `NOTICE` and in `scripts/vendored-sources.tsv`.

The module is gated on the `std` feature in `lib.rs`: `mmap(2)` and `RawFd` are `std`-only by Rust's design, so the `no_std` build does not compile it at all. It is here because the pack store maps pack files, and the pack store's own query path is where mapping pays: a store with a hundred packs pays the map and the unmap on every query otherwise.

The shape is the upstream one: `MmapOptions` is the builder that holds the offset, length, stack and populate settings; `Mmap` is the read-only handle and `MmapMut` the writable one; the platform layer below owns the actual system calls.

## Interface
- `pub struct Mmap` — the read-only mapping; `Deref<Target = [u8]>`.
  - `pub unsafe fn map<T: MmapAsRawDesc>(file: T) -> io::Result<Mmap>`.
  - `pub fn make_mut(self) -> io::Result<MmapMut>`.
  - `pub fn advise(&self, advice: Advice) -> io::Result<()>` and `pub unsafe fn unchecked_advise(&self, advice: UncheckedAdvice) -> io::Result<()>` — Unix only.
  - `pub fn advise_range(&self, advice: Advice, offset: usize, len: usize) -> io::Result<()>` and `pub unsafe fn unchecked_advise_range(...)` — Unix only.
  - `pub fn lock(&self) -> io::Result<()>`, `pub fn unlock(&self) -> io::Result<()>` — Unix only.
  - `pub fn as_ptr(&self) -> *const u8`, `pub fn len(&self) -> usize`.
- `pub struct MmapMut` — the writable mapping; `Deref<Target = [u8]>` and `DerefMut`.
  - `pub unsafe fn map_mut<T: MmapAsRawDesc>(file: T) -> io::Result<MmapMut>`.
  - `pub fn map_anon(length: usize) -> io::Result<MmapMut>`.
  - `pub fn flush(&self) -> io::Result<()>`, `pub fn flush_async(&self) -> io::Result<()>`, `pub fn flush_range(&self, offset, len)`, `pub fn flush_async_range(&self, offset, len)`.
  - `pub fn make_read_only(self) -> io::Result<Mmap>`, `pub fn make_exec(self) -> io::Result<Mmap>`.
  - `pub fn advise(&self, advice: Advice)`, `pub unsafe fn unchecked_advise(&self, advice: UncheckedAdvice)`, `pub fn advise_range(...)`, `pub unsafe fn unchecked_advise_range(...)` — Unix only.
  - `pub fn lock(&self) -> io::Result<()>`, `pub fn unlock(&self) -> io::Result<()>` — Unix only.
  - `pub fn as_ptr(&self) -> *const u8`, `pub fn as_mut_ptr(&mut self) -> *mut u8`, `pub fn len(&self) -> usize`.
- `pub struct MmapOptions` — `new()`, `offset(u64)`, `len(usize)`, `stack()`, `populate()`, and the mapping entry points `map`, `map_exec`, `map_mut`, `map_copy`, `map_copy_read_only` (all `unsafe`) plus `map_anon()`.
- `pub trait MmapAsRawDesc` — the trait a type must implement to be mapped.
- `pub struct MmapRawDescriptor` — the platform's raw descriptor type, a newtype over the raw fd or handle; on the fallback target it carries a lifetime and wraps a `&File`.
- `pub enum Advice`, `pub enum UncheckedAdvice` — the `madvise` values, re-exported on Unix only. Both variants hand the number to `madvise(2)`, but only after the platform's own check: `advice::is_available` says whether this platform has that advice at all, and `platform::refuse_unavailable` turns down the ones it does not have instead of handing over a number the kernel would read as something else.
- `platform`: [platform](./platform/EGM.md) — the per-OS `MmapInner` and the shared helpers. The module itself is private; `MmapAsRawDesc` and `MmapRawDescriptor` are re-exported at the module root, while `MmapInner` (map/map_exec/map_mut/map_copy/map_copy_read_only/map_anon, flush, flush_async, make_read_only, make_exec, make_mut, advise, lock, unlock, ptr, mut_ptr, len), `page_size()`, `file_len()` and `file_len_for_desc()` are crate-internal.

## Invariants
- The mapping is `unsafe` to create because the caller must guarantee the file's length and the mapping's lifetime: the `map`/`map_mut`/`map_copy` entry points take `unsafe` for that reason, and the only safe wrapper on `MmapOptions` is `map_anon`, which maps no file.
- `MmapOptions::offset` is not required to be a multiple of the page size: on Unix it is silently aligned *down* and the length extended to match, and on Windows it is refused against the allocation granularity with `ERROR_MAPPED_ALIGNMENT`. A length that overflows `isize` and an offset past the end of the file are both refused as an `io::Error` of kind `InvalidData`.
- A mapping's length is the file's length minus the offset when no length is given, and the mapping never extends past the end of the file.
- `make_read_only`, `make_exec` and `make_mut` consume the handle and produce a new one: a mapping's protection cannot be loosened in place.
- `flush` and `flush_range` are what make a write durable; `flush_async` returns before the write reaches the device.
- `lock`/`unlock` take and release a *page* lock on the mapped range — `mlock`/`munlock` on Unix, `VirtualLock`/`VirtualUnlock` on Windows. No file lock is taken anywhere in the module.
- Every unsafe operation is a thin wrapper over a platform call whose contract the platform layer documents.

## Side Effects
- Maps memory: `mmap`/`munmap`/`msync`/`madvise`/`mlock`/`munlock` on Unix, `CreateFileMappingW`/`MapViewOfFile`/`UnmapViewOfFile`/`FlushViewOfFile`/`VirtualLock`/`VirtualUnlock` on Windows.
- Only the Windows mapping owns a handle: it duplicates the caller's and closes it on drop. The Unix `MmapInner` holds a pointer and a length and owns no descriptor.
- `flush` writes dirty pages back to the device; `lock` takes a page lock, which is process-private and no other process can observe.
- The module never opens a file itself: the caller supplies the `File` or the raw descriptor.

## Verification
- Run: `cargo test --release --locked --workspace`
